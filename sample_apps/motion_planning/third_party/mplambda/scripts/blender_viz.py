#!/usr/bin/env blender --python
import bpy

bpy.ops.object.delete(use_global=False)


for a in bpy.context.screen.areas:
    if a.type == 'VIEW_3D':
        a.spaces.active.clip_end = 50000
        a.spaces.active.clip_start = 10

deg = 3.1415926535897932384626433832795028841968 / 180

cam = bpy.data.objects['Camera'];
cam.data.clip_end = 50000
cam.data.clip_start = 100
cam.location = [ 1600, 600, 1200 ]
cam.rotation_euler = [ 52.2 * deg, 0, 102 * deg ]


env = bpy.data.objects.new("env", None)
bpy.context.collection.objects.link(env)
bpy.ops.wm.collada_import(filepath="../resources/se3/Twistycool_env.dae", auto_connect=False, fix_orientation=True)
bpy.ops.object.transform_apply()
for obj in bpy.context.selected_objects:
    obj.parent = env;
    # obj.constraints.new(type='CHILD_OF')
    # obj.constraints['Child Of'].target = env

env.rotation_mode = 'AXIS_ANGLE'
env.rotation_axis_angle = (-90*deg, 1, 0, 0)
bpy.ops.object.transform_apply()
    
robot = bpy.data.objects.new("robot", None);
bpy.context.collection.objects.link(robot)
bpy.ops.wm.collada_import(filepath="../resources/se3/Twistycool_robot.dae", auto_connect=True);
bpy.ops.object.transform_apply()
# bpy.ops.object.origin_set(type='ORIGIN_GEOMETRY', center='BOUNDS')
# bpy.ops.object.origin_set(type='ORIGIN_CENTER_OF_MASS')
for obj in bpy.context.selected_objects:
    obj.parent = robot

robot.rotation_mode = 'AXIS_ANGLE'
robot.rotation_axis_angle = (-90*deg, 1, 0, 0)
bpy.ops.object.transform_apply()

robot.rotation_mode = 'QUATERNION'
    
for obj in robot.children:
    # obj.location = (0,0,0)
    if obj.data is not None:
        x = y = z = n = 0
        n += len(obj.data.vertices)
        for v in obj.data.vertices:
            x += v.co[0]
            y += v.co[1]
            z += v.co[2]

        print(obj.location)
        print(x/n, y/n, z/n, n)
        obj.location = (-x/n, -y/n, -z/n)
        bpy.context.view_layer.objects.active = obj
        bpy.ops.object.transform_apply()
        
#bpy.ops.object.origin_set(type='ORIGIN_CURSOR')
#saved_location = bpy.context.scene.cursor.location
#bpy.context.scene.cursor.location = (0, 0, 0)
#bpy.ops.object.origin_set(type='ORIGIN_CURSOR')
#bpy.context.scene.cursor.location = saved_location

   
    # if obj.data is None:
    #     print("obj.data is None")
    # else:
    #     #bpy.ops.object.mode_set(mode = 'OBJECT') 
    #     s = i = 0
    #     for v in obj.data.vertices:
    #         # if v.select:
    #         s += v.co[2]
    #         i += 1
    #     print(s/i)
    #     # bpy.ops.object.mode_set(mode = 'EDIT')

    
keyFrame = 1
for line in open("Twistycool.3.path", 'r').readlines():
    l = line.strip()
    if not l:
        continue
    q = [float(x) for x in l.split(' ')]
    robot.rotation_quaternion = ( q[6], q[3], q[4], q[5] )
    robot.location = ( q[0], q[1], q[2] )
    robot.keyframe_insert(data_path='rotation_quaternion', frame = keyFrame)
    robot.keyframe_insert(data_path='location', frame = keyFrame)
    keyFrame = keyFrame + 30

