//! Unit registry: the units this layer recognises and the exact affine conversions between them
//! (value_to = a * value_from + b). Shared by range checks and derivation recomputation, so a
//! value recorded in degF is range-checked in degC instead of being rejected or misread.

/// (from, to, a, b): to = a * from + b
const CONVERSIONS: &[(&str, &str, f64, f64)] = &[
    ("degC", "K", 1.0, 273.15),
    ("degC", "degF", 9.0 / 5.0, 32.0),
    ("hPa", "Pa", 100.0, 0.0),
    ("hPa", "kPa", 0.1, 0.0),
    ("%", "1", 0.01, 0.0),
    ("m", "cm", 100.0, 0.0),
    ("m", "km", 0.001, 0.0),
    ("m", "ft", 1.0 / 0.3048, 0.0),
    ("m/s", "km/h", 3.6, 0.0),
    ("mS/cm", "uS/cm", 1000.0, 0.0),
    ("mg/L", "ppm", 1.0, 0.0),
    ("dbar", "Pa", 10_000.0, 0.0),
];

/// Units recognised without conversion (dimensionless or used as-is).
const KNOWN: &[&str] = &["degC", "K", "degF", "hPa", "Pa", "kPa", "%", "1", "m", "cm", "km", "ft", "m/s", "km/h", "mS/cm", "uS/cm",
                         "mg/L", "ppm", "dbar", "pH", "lx", "uT", "m/s2", "deg", "rad/s", "dB", "Hz", "s", "PSU", "NTU", "W/m2", "V", "A"];

pub fn known(unit: &str) -> bool {
    KNOWN.contains(&unit)
}

/// The affine map (a, b) such that to = a * from + b, if one exists (directly or by inversion).
pub fn affine(from: &str, to: &str) -> Option<(f64, f64)> {
    if from == to {
        return Some((1.0, 0.0));
    }
    for &(f, t, a, b) in CONVERSIONS {
        if f == from && t == to {
            return Some((a, b));
        }
        if t == from && f == to {
            return Some((1.0 / a, -b / a));
        }
    }
    // one hop through a shared unit (e.g. K -> degF via degC)
    for &(f, t, _, _) in CONVERSIONS {
        for mid in [f, t] {
            if mid != from && mid != to {
                if let (Some((a1, b1)), Some((a2, b2))) = (affine_direct(from, mid), affine_direct(mid, to)) {
                    return Some((a2 * a1, a2 * b1 + b2));
                }
            }
        }
    }
    None
}

fn affine_direct(from: &str, to: &str) -> Option<(f64, f64)> {
    CONVERSIONS.iter().find_map(|&(f, t, a, b)| {
        if f == from && t == to {
            Some((a, b))
        } else if t == from && f == to {
            Some((1.0 / a, -b / a))
        } else {
            None
        }
    })
}

pub fn convert(x: f64, from: &str, to: &str) -> Option<f64> {
    affine(from, to).map(|(a, b)| a * x + b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_are_exact_and_invertible() {
        assert_eq!(convert(20.0, "degC", "K"), Some(293.15));
        assert!((convert(68.0, "degF", "degC").unwrap() - 20.0).abs() < 1e-12);
        assert!((convert(293.15, "K", "degF").unwrap() - 68.0).abs() < 1e-9);
        assert_eq!(convert(1013.25, "hPa", "Pa"), Some(101325.0));
        assert!(convert(1.0, "degC", "hPa").is_none());
        assert!(known("PSU") && !known("furlongs"));
    }
}
