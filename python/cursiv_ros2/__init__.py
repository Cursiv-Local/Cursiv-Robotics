"""Cursiv Robotics ROS 2 evidence capture (EXPERIMENTAL).

    python -m cursiv_ros2 discover
    python -m cursiv_ros2 capture --robot rover-01 --mission lab-1 --topics '/sensors/*' --real --station http://127.0.0.1:8750

The capture core, adapters, agent and MCAP conversion work without ROS; `node` needs rclpy.
"""
