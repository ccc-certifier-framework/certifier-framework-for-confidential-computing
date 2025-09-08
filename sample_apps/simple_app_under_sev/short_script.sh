export CERTIFIER_ROOT=/home/jlm/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$(pwd)
export DOMAIN_NAME="datica-test"
export POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
export POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
export POLICY_STORE_FILE_NAME="policy_store.$DOMAIN_NAME"

echo "Root: $CERTIFIER_ROOT"
echo "Example: $EXAMPLE_DIR"
echo "Domain: $DOMAIN_NAME"
echo "Policy key: $POLICY_KEY_FILE_NAME"
echo "Policy cert: $POLICY_CERT_FILE_NAME"
echo "Policy store: $POLICY_STORE_FILE_NAME"


$CERTIFIER_ROOT/certifier_service/simpleserver  \
   --policy_key_file="$POLICY_KEY_FILE_NAME" --policy_cert_file="$POLICY_CERT_FILE_NAME"  \
   --policyFile=policy.bin --readPolicy=true

sleep 2

$EXAMPLE_DIR/sev_example_app.exe  \
  --data_dir="$EXAMPLE_DIR/app2_data/" --operation=cold-init \
  --domain_name="$DOMAIN_NAME" \
  --policy_store_file="$POLICY_STORE_FILE_NAME" --print_all=true

$EXAMPLE_DIR/sev_example_app.exe  \
  --data_dir="$EXAMPLE_DIR/app1_data/" --operation=cold-init \
  --domain_name="$DOMAIN_NAME" \
  --policy_store_file="$POLICY_STORE_FILE_NAME" --print_all=true

sleep 1

$EXAMPLE_DIR/sev_example_app.exe \
   --data_dir="$EXAMPLE_DIR/app1_data/" --operation=get-certified \
   --domain_name="$DOMAIN_NAME" \
   --policy_store_file="$POLICY_STORE_FILE_NAME" --print_all=true

sleep 1

$EXAMPLE_DIR/sev_example_app.exe  \
  --data_dir="$EXAMPLE_DIR/app2_data/" --operation=get-certified \
  --domain_name="$DOMAIN_NAME" \
  --policy_store_file="$POLICY_STORE_FILE_NAME" --print_all=true

sleep 3

$EXAMPLE_DIR/sev_example_app.exe  \
   --data_dir="$EXAMPLE_DIR/app2_data/" --operation=run-app-as-server \
   --domain_name="$DOMAIN_NAME" \
   --policy_store_file="$POLICY_STORE_FILE_NAME" --print_all=true

sleep 3

$EXAMPLE_DIR/sev_example_app.exe \
   --data_dir="$EXAMPLE_DIR/app1_data/" --operation=run-app-as-client \
   --domain_name="$DOMAIN_NAME" \
   --policy_store_file="$POLICY_STORE_FILE_NAME" --print_all=true
exit
