

import random 
order_id = 0

for id in range(0, 501):
    product_id = random.randint(0, 2000)
    price_per_unit = random.randrange(1, 300)
    quantity = random.randint(1, 20)
    total = quantity * price_per_unit
    ret = str(id) + "," + str(order_id) + "," + str(product_id) + "," + str(price_per_unit)+ "," + str(quantity) + "," + str(total)
    print(ret)
    order_id += (random.randint(0, 3) > 2)