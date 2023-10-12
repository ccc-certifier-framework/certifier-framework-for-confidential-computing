/* Copyright (C) 2021 Advanced Micro Devices, Inc. */
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <uuid/uuid.h>
#include <sev_cert_table.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpplusplus */

const char vcek_guid[] = "63da758d-e664-4564-adc5-f4b93be8accd";
const char ask_guid[] = "4ab7b379-bbac-4fe4-a02f-05aef327c782";
const char ark_guid[] = "c0b406a4-a803-4952-9743-3fb6014cd0ae";

static const struct cert_table_entry terminator = {
    .guid = {0},
    .offset = 0,
    .length = 0,
};

int cert_table_alloc(struct cert_table *table, size_t nr_entries) {
#define MIN_NR_ENTRIES (1) /* Terminator entry, all zeros */

  int    rc = EXIT_FAILURE;
  size_t entry_size = sizeof(*table->entry);

  if (!table || nr_entries < MIN_NR_ENTRIES) {
    rc = EINVAL;
    goto out;
  }

  /* Check that the requested table size will not overflow */
  if ((entry_size * (nr_entries + 1)) < entry_size
      || (entry_size * (nr_entries + 1)) < nr_entries) {
    rc = EOVERFLOW;
    goto out;
  }

  /* Include an additional empty entry as a terminator */
  table->entry = (struct cert_table_entry *)calloc(entry_size, nr_entries + 1);
  if (!table->entry) {
    rc = ENOMEM;
    goto out;
  }

  /* The offset of the first certificate is simply the size of the table */
  table->entry[0].offset = entry_size * (nr_entries + 1);

  /*
   * To simplify iterating over the table entries, initialize the guids
   * to non-zero values in order to differentiate them from the last, all-
   * zeros entry.
   */
  for (size_t i = 0; i < nr_entries; i++) {
    struct cert_table_entry *entry = table->entry + i;

    memset(&entry->guid, 0xff, sizeof(entry->guid));
  }

  rc = EXIT_SUCCESS;
out:
  return rc;
}

void cert_table_free(struct cert_table *table) {
  if (table) {
    free(table->entry);
    table->entry = NULL;
  }
}

size_t cert_table_get_size(const struct cert_table *table) {
  return table ? table->entry[0].offset : 0;
}

static inline bool entry_is_empty(struct cert_table_entry *entry) {
  return entry->length == 0;
}

static bool entry_is_terminator(struct cert_table_entry *entry) {
  return memcmp(entry, &terminator, sizeof(terminator)) == 0;
}

int cert_table_add_entry(struct cert_table *table,
                         const char *       guid,
                         size_t             cert_size) {
  int    rc = -EXIT_FAILURE;
  size_t offset = 0;

  if (!table || !table->entry || !guid || cert_size == 0) {
    rc = -EINVAL;
    goto out;
  }

  offset = cert_table_get_size(table);
  if (offset == 0) {
    rc = ENODATA;
    goto out;
  }

  for (size_t i = 0; !entry_is_terminator(table->entry + i); i++) {
    struct cert_table_entry *entry = table->entry + i;

    if (!entry_is_empty(entry)) {
      offset += entry->length;
      if (offset < entry->length) {
        rc = EOVERFLOW;
        goto out;
      }
      continue;
    }

    /* Found an empty table entry, so fill it */
    rc = uuid_parse(guid, entry->guid);
    if (rc != 0) {
      rc = EINVAL;
      goto out;
    }

    entry->offset = offset;
    entry->length = cert_size;
    rc = EXIT_SUCCESS;
    goto out;
  }

  /* All cert table entries searched */
  fprintf(stderr, "%s: cert table is full.\n", __func__);
  rc = ENOBUFS;
out:
  return rc;
}

int cert_table_get_certs_size(const struct cert_table *table, size_t *size) {
  int    rc = EXIT_FAILURE;
  size_t certs_size = 0;

  if (!table || !size) {
    rc = EINVAL;
    goto out;
  }

  for (size_t i = 0; !entry_is_terminator(table->entry + i); i++) {
    struct cert_table_entry *entry = table->entry + i;

    certs_size += entry->length;
    if (certs_size < entry->length) {
      rc = EOVERFLOW;
      goto out;
    }
  }

  *size = certs_size;
  rc = EXIT_SUCCESS;
out:
  return rc;
}

int cert_table_copy(const struct cert_table *table,
                    uint8_t *                buffer,
                    size_t                   size) {
  int    rc = EXIT_FAILURE;
  size_t table_size = 0, offset = 0;

  if (!table || !buffer) {
    rc = EINVAL;
    goto out;
  }

  table_size = cert_table_get_size(table);
  if (table_size == 0) {
    rc = EINVAL;
    goto out;
  }

  if (table_size > size) {
    rc = ENOBUFS;
    goto out;
  }

  for (size_t i = 0; !entry_is_terminator(table->entry + i); i++) {
    struct cert_table_entry *entry = table->entry + i;

    memcpy(buffer + offset, entry, sizeof(*entry));
    offset += sizeof(*entry);
  }

  rc = EXIT_SUCCESS;
out:
  return rc;
}

int cert_table_get_entry(const struct cert_table *table,
                         struct cert_table_entry *entry,
                         const char *             guid) {
  int    rc = EXIT_FAILURE;
  uuid_t id = {0};

  if (!table || !entry || !guid) {
    rc = EINVAL;
    goto out;
  }

  rc = uuid_parse(guid, id);
  if (rc != 0) {
    rc = EINVAL;
    goto out;
  }

  /* Return ENOENT if the GUID is not found in the table */
  rc = ENOENT;
  for (size_t i = 0; !entry_is_terminator(table->entry + i); i++) {
    struct cert_table_entry *current = table->entry + i;

    if (memcmp(current->guid, id, sizeof(id)) == 0) {
      *entry = *current;
      rc = EXIT_SUCCESS;
      break;
    }
  }
out:
  return rc;
}

int cert_table_append_cert(const struct cert_table *table,
                           uint8_t *                buffer,
                           size_t                   buffer_size,
                           const char *             guid,
                           uint8_t *                cert,
                           size_t                   cert_size) {
  int    rc = EXIT_FAILURE;
  size_t table_size = 0, certs_size = 0, total_size = 0;
  uuid_t id = {0};

  if (!table || !buffer || !cert || cert_size == 0) {
    rc = EINVAL;
    goto out;
  }

  table_size = cert_table_get_size(table);
  if (table_size == 0) {
    rc = EINVAL;
    goto out;
  }

  rc = cert_table_get_certs_size(table, &certs_size);
  if (rc != EXIT_SUCCESS) {
    rc = EINVAL;
    goto out;
  }

  total_size = table_size + certs_size;
  if (total_size < certs_size || buffer_size < total_size) {
    rc = EOVERFLOW;
    goto out;
  }

  rc = uuid_parse(guid, id);
  if (rc != 0) {
    rc = EINVAL;
    goto out;
  }

  /* Return ENOENT if the GUID is not found in the table */
  rc = ENOENT;
  for (size_t i = 0; !entry_is_terminator(table->entry + i); i++) {
    struct cert_table_entry *entry = table->entry + i;

    if (memcmp(entry->guid, id, sizeof(id)) != 0)
      continue;

    /* GUID entry found. Confirm that the cert sizes match. */
    if (entry->length != cert_size) {
      rc = EINVAL;
      goto out;
    }

    memcpy(buffer + entry->offset, cert, cert_size);
    rc = EXIT_SUCCESS;
    break;
  }
out:
  return rc;
}

#ifdef __cplusplus
}
#endif /* __cpplusplus */
