from droplet.client.client import DropletConnection
from anna.client import AnnaTcpClient
from anna.lattices import PriorityLattice
import os, time, random

class MPLRobot():
    """
    A wrapper class that handles registering and executing functions on Droplet. It also provides helper functions for polling Anna KVS
    """
    def __init__(self, droplet, anna, typ='fetch', function_name=None):
        """
        Sets up a unique key for the robot based on timestamp. Also registers the function with Droplet based on the typ provided.

        droplet: An instance of `DropletConnection` used to register and 
        anna: An instance of `AnnaTcpClient` used for polling
        typ: (Optional) Which kind of experiment to run. (TODO for what values this can take)
        function_name: (Optional) If the function has been previously registered on droplet, just use it directly
        """
        self.droplet = droplet
        self.anna = anna
        self.typ = typ
        self.function_name = function_name
        self.unique_key = "solution_path_{}".format(time.time())
        if function_name == None:
            self.register()
        else:
            self.fn = self.droplet.get_function(function_name)

    def register(self):
        """
        Run on initialization, registers the below function with droplet.
        """
        def fn(s, unique_key):
            """

            """
            # Test function that puts a random priority
            rand = random.random()
            time.sleep(rand)
            pl = PriorityLattice(1.0 - rand, b"Test")

            elb_address = '127.0.0.1' # or the address of the ELB returned by the 
            anna_client_args = {
                    'elb_addr': elb_address, 
                    'ip': elb_address, 
                    'local': True, 
                    'offset': 1
                    }
            anna_client = safe_create_anna_client(anna_client_args)
            anna_client.put(unique_key, pl)
            return "{} executed with rand {}".format(unique_key, rand)
            #registration_cmd = '''./build/mpl_lambda_pseudo --scenario se3     --algorithm cforest     --coordinator "$COORDINATOR"     --jobs 10     --env se3/Twistycool_env.dae     --robot se3/Twistycool_robot.dae     --start 0,1,0,0,270,160,-380     --goal 0,1,0,0,270,160,-400     --min 53.46,-21.25,-476.86     --max 402.96,269.25,-91.0     --time-limit 120     --check-resolution 0.1 --thread_id 1
            #'''
            #cmd = os.system(registration_cmd)
            #return cmd
        self.fn = self.droplet.register(fn, 'fn')
    
    def execute(self, num_lambdas=1):
        # TODO: more than one lambda seems to have issues working
        """
        Execute num_lambdas runs of the function on the droplet cluster. Run the function passing in the unique_key, so the function can use the same unique_key to store information in Anna.
        """
        return [self.fn(self.unique_key) for _ in range(num_lambdas)]

    def poll(self):
        """
        Checks Anna with the unique_key and returns the cost and value if the key exists, otherwise infinity.
        """
        pl = self.anna.get(self.unique_key)[self.unique_key]
        if pl is None:
            return float('inf'), b""
        return pl.priority, pl.value


def safe_create_anna_client(anna_client_args, initial_offset=0, num_retries=10):
    """
    Creating multiple anna clients is sometimes an issue because each one needs a separate offset. Safely try creating multiple clients in a more reliable way.

    anna_client_args: initialization arguments for `AnnaTcpClient`
    initial_offset: offset to start checking for available clients
    num_retries: how many clients to look for
    """
    for offset in range(initial_offset, initial_offset + num_retries):
        try:
            anna_client_args['offset'] = offset
            return AnnaTcpClient(**anna_client_args)
        except Exception as e:
            continue
    raise e

"""
The main function below sets up all the required objects, and records times of cost changes. Changes are only recorded if they are less, because by Anna only the best solution is kept.
"""
# TODO: Is the above assumption of only appending to the array if solution is lower valid?
# TODO: execute(num_lambdas > 1) doesn't work. It seems like it has something to do with local execution for Anna only allocating 1 ELB address and not releasing it after (in the init method for AnnaTcpClient)

if __name__ == "__main__":
    elb_address = '127.0.0.1' # or the address of the ELB returned by the 
    #import pdb; pdb.set_trace()
    droplet = DropletConnection(elb_address, elb_address, local=True)
    anna_client_args = {
            'elb_addr': elb_address, 
            'ip': elb_address, 
            'local': True, 
            'offset': 1
            }
    anna_client = safe_create_anna_client(anna_client_args)
    mpl_robot = MPLRobot(droplet, anna_client, function_name=None) # replace the None with the preregistered function_name

    times, costs = [0], [float('inf')] # initialize for usage later
    time_limit_in_seconds = 5
    start_time = time.time()
    fns = mpl_robot.execute(num_lambdas=1)
    while time.time() - start_time < time_limit_in_seconds:
        curr_time = time.time() - start_time
        priority, value = mpl_robot.poll()
        if priority < costs[-1]:
            times.append(curr_time)
            costs.append(priority)
    print(times, costs)
    #for f in fns:
    #    print(f.get())


