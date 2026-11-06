"""Simulated ROS 2 publishers for the integration test (run with ROS 2 sourced).

Publishes known values so the test can check what was captured:
- /sim/temperature  sensor_msgs/Temperature, 20 Hz, temperature = 20 + seq/100, variance 0.01
- /sim/imu          sensor_msgs/Imu, 100 Hz
- /sim/fix          sensor_msgs/NavSatFix, 2 Hz
- /sim/note         std_msgs/String, 10 Hz
- /sim/camera/compressed  sensor_msgs/CompressedImage, 2 Hz (a tiny PNG)
Writes the number of messages published per topic to the file given as argv[2] at exit.
"""
import json
import sys
import time

import rclpy
from rclpy.node import Node
from sensor_msgs.msg import CompressedImage, Imu, NavSatFix, NavSatStatus, Temperature
from std_msgs.msg import String

PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082")


def main():
    duration = float(sys.argv[1])
    rclpy.init()
    n = Node("sim_sensors")
    pubs = {"/sim/temperature": n.create_publisher(Temperature, "/sim/temperature", 10),
            "/sim/imu": n.create_publisher(Imu, "/sim/imu", 10),
            "/sim/fix": n.create_publisher(NavSatFix, "/sim/fix", 10),
            "/sim/note": n.create_publisher(String, "/sim/note", 10),
            "/sim/camera/compressed": n.create_publisher(CompressedImage, "/sim/camera/compressed", 10)}
    count = {k: 0 for k in pubs}

    def stamp(m):
        m.header.stamp = n.get_clock().now().to_msg()
        m.header.frame_id = "sim"
        return m

    def temp():
        m = stamp(Temperature())
        m.temperature, m.variance = 20 + count["/sim/temperature"] / 100, 0.01
        pubs["/sim/temperature"].publish(m)
        count["/sim/temperature"] += 1

    def imu():
        m = stamp(Imu())
        m.linear_acceleration.z = 9.81
        pubs["/sim/imu"].publish(m)
        count["/sim/imu"] += 1

    def fix():
        m = stamp(NavSatFix())
        m.status.status = NavSatStatus.STATUS_FIX
        m.latitude, m.longitude, m.altitude = 45.5, -122.6, 30.0
        m.position_covariance = [4.0, 0, 0, 0, 4.0, 0, 0, 0, 9.0]
        m.position_covariance_type = NavSatFix.COVARIANCE_TYPE_DIAGONAL_KNOWN
        pubs["/sim/fix"].publish(m)
        count["/sim/fix"] += 1

    def note():
        pubs["/sim/note"].publish(String(data=f"note {count['/sim/note']}"))
        count["/sim/note"] += 1

    def cam():
        m = stamp(CompressedImage())
        m.format, m.data = "png", list(PNG)
        pubs["/sim/camera/compressed"].publish(m)
        count["/sim/camera/compressed"] += 1

    for period, f in ((0.05, temp), (0.01, imu), (0.5, fix), (0.1, note), (0.5, cam)):
        n.create_timer(period, f)
    end = time.monotonic() + duration
    while time.monotonic() < end:
        rclpy.spin_once(n, timeout_sec=0.01)
    open(sys.argv[2], "w").write(json.dumps(count))
    n.destroy_node()
    rclpy.shutdown()


if __name__ == "__main__":
    main()
