
# Connection Process

Actors:
* Robot
* Coordinator
* Lambdas x p

Robot
1. Connect to coordinator, send
  * problem ID
  * problem definition
  * time bound

Coordinator
2. Launch lambda (x p), with launch parameters:
  * coordinator ip and port
  * problem ID
  * problem definition
3. RRT loop
  * if `Path` received, broadcast `Done`, return path to robot
4. CForest Loop
  * if `Path` received, broadcast `Path` to connections

Lambda
3. Load problem
4. Connect to coordinator, send problem ID (Hello Packet)
5. Start solver (RRT)
   * Once solved, send (Path Packet) and terminate
   * If connection dropped or `Done` received, terminate
5. Start solver (CForest)
   * If path found or impreved, send `Path` to coordinator
   * if path recieved from coordinator, update graph
   * if connection dropped or `Done` received, terminate

# Coordinator design

When robot initiates a problem, coordinator adds the problem to a hash table, and starts the lambda launches.

When problem is done, coordinator removes the problem from the hash table.

Any outstanding Hello packets to a non-existant problem will recieved a Done packet.


# Packets

All packets start with a 4-byte type, followed by a 4-byte length.
The length is the number of bytes of the entire packet, including the
type and length fields (thus the minimum value of length is 8).  All
data is sent in network byte order (big endian).

## Problem (SE3):

type (4):
  0xdbb69672 (S = float)
  0xdbb69673 (S = double)
len (4):
start: (6 x sizeof(S))
goal: (6 x sizeof(S))
min: (3 x sizeof(S))
max: (3 x sizeof(S))
robot: (string)
env: (string)


## Hello

type (4): 0x3864caca
len (4): 16
ID (8): <problem id>

## Done

type (4): 0xbafc1115
len (4): 0

## Path (float)

type (4): 0x96c2f344
len (4): (# of waypoints) x (# DOF) x 4 + 8
waypoints: ...

## Path (double)

type (4): 0x96c2f345
len (4): (# of waypoints) x (# DOF) x 8 + 8
waypoints: ...


