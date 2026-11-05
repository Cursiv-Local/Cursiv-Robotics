"""Experimental API: may change in any release. See docs/API.md."""
from __future__ import annotations

from cursiv_ros2.agent import Frontier, StreamingAgent  # noqa: F401
from cursiv_ros2.capture import CaptureConfig, CaptureCore, TopicConfig  # noqa: F401


def export_mcap(package, out, *, verification: dict, allow_unverified: bool = False) -> dict:
    """Package -> MCAP (raw ROS 2 channels, JSON observations, foxglove.LocationFix). Needs `mcap`."""
    from cursiv_ros2.mcap_io import export_mcap as f
    return f(package, out, verification=verification, allow_unverified=allow_unverified)


def import_mcap(path, core: CaptureCore, *, topics=None) -> dict:
    """MCAP -> signed records through a CaptureCore. Needs `mcap` (and `mcap-ros2-support` to decode CDR)."""
    from cursiv_ros2.mcap_io import import_mcap as f
    return f(path, core, topics=topics)


def ros2_run(core: CaptureCore, patterns, **kw) -> dict:
    """Run the ROS 2 capture node (needs rclpy, i.e. a sourced ROS 2 installation)."""
    from cursiv_ros2.node import run
    return run(core, patterns, **kw)
