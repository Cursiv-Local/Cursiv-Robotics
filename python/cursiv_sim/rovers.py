"""The three initial research agents. Each produces observations through the same API a
physical robot would use; all of them are labelled synthetic."""
from __future__ import annotations

from .identity import sha256_hex
from .robot import RobotAgent
from .world import Site, png

CAL = {"calibrated_utc": "2026-10-01T00:00:00Z", "valid_until_utc": "2027-04-01T00:00:00Z",
       "reference": "simulated bench calibration", "certificate_sha256": None}


def sensor(robot: str, name: str, kind: str, calibration=CAL) -> dict:
    return {"sensor_id": f"{robot}-{name}", "sensor_type": kind, "model": "sim-1", "calibration": calibration}


class Rover:
    lane = 0
    role = ""

    def __init__(self, agent: RobotAgent, site: Site):
        self.agent, self.site = agent, site
        self.bias = {}          # fault injection: observation_type -> added offset

    def step(self, i: int, n: int) -> list[dict]:
        raise NotImplementedError

    def _obs(self, ty, name, kind, value, unit, u, lat, lon, **kw):
        v = value + self.bias.get(ty, 0.0)
        return self.agent.record(self.agent.observation(ty, sensor=sensor(self.agent.robot_id, name, kind), value=round(v, 3),
                                                        unit=unit, uncertainty=u, lat=lat, lon=lon, **kw))


class GeologyRover(Rover):
    """Rover 01: soil moisture, pH and soil temperature."""
    lane, role = 0, "geological survey"

    def step(self, i, n):
        lat, lon = self.site.point(i, n, self.lane)
        s = self.site
        return [self._obs("soil_moisture", "tdr", "tdr_probe", s.soil_moisture(lat, lon) + s.noise(0.4), "%", 0.8, lat, lon),
                self._obs("soil_ph", "ph", "ph_electrode", s.soil_ph(lat, lon) + s.noise(0.03), "pH", 0.05, lat, lon),
                self._obs("soil_temperature", "thermistor", "thermistor", s.soil_temperature(lat, lon) + s.noise(0.05), "degC", 0.1, lat, lon)]


class EnvironmentRover(Rover):
    """Rover 02: air temperature, relative humidity and pressure."""
    lane, role = 1, "environmental monitoring"

    def step(self, i, n):
        lat, lon = self.site.point(i, n, self.lane)
        s = self.site
        return [self._obs("air_temperature", "pt100", "rtd", s.air_temperature(lat, lon) + s.noise(0.05), "degC", 0.15, lat, lon),
                self._obs("relative_humidity", "hygro", "capacitive_rh", s.humidity(lat, lon) + s.noise(0.3), "%", 1.5, lat, lon),
                self._obs("air_pressure", "baro", "mems_barometer", s.pressure(lat, lon) + s.noise(0.05), "hPa", 0.12, lat, lon)]


class ImagingRover(Rover):
    """Rover 03: images of each survey point (attachments), with a co-located air temperature
    reading that can be cross-checked against Rover 02."""
    lane, role = 1, "imaging and documentation"

    def step(self, i, n):
        lat, lon = self.site.point(i, n, self.lane)
        img = png(48, 32, seed=i)
        sha = sha256_hex(img)
        self.agent.upload(img, sha)
        out = [self.agent.record(self.agent.observation(
            "image", sensor=sensor(self.agent.robot_id, "cam", "rgb_camera"), lat=lat, lon=lon,
            attachments=[{"sha256": sha, "size": len(img), "media_type": "image/png", "role": "raw"}],
            processing=[{"step": "png_encode", "software": "cursiv-sim", "version": "0.1.0", "parameters": {"width": 48, "height": 32}}]))]
        out.append(self._obs("air_temperature", "thermo", "thermistor",
                             self.site.air_temperature(lat, lon) + self.site.noise(0.05), "degC", 0.2, lat, lon))
        return out


ROVERS = {"rover-01": GeologyRover, "rover-02": EnvironmentRover, "rover-03": ImagingRover}
