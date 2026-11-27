import numpy as np
import pandas as pd

DEVICE_TYPES = ["camera", "thermostat", "smart_plug"]
NUM_COLS = ["packet_rate", "avg_packet_size", "byte_rate", "flow_duration", "unique_dst_ports",
            "syn_ratio", "failed_conn_ratio", "telnet_ratio", "outbound_ratio"]
ATTACK_TYPES = ["DDoS", "PortScan", "BruteForce", "Exfiltration"]

DEVICE_NAMES_AR = {"camera": "كاميرا", "thermostat": "منظّم حرارة", "smart_plug": "مقبس ذكي"}
ATTACK_NAMES_AR = {"Normal": "حركة طبيعية", "DDoS": "إغراق DDoS", "PortScan": "فحص المنافذ",
                   "BruteForce": "تخمين كلمات المرور", "Exfiltration": "تسريب البيانات"}
FEATURE_NAMES_AR = {
    "packet_rate": "معدل الحزم (حزمة/ث)",
    "avg_packet_size": "متوسط حجم الحزمة (بايت)",
    "byte_rate": "معدل البيانات (بايت/ث)",
    "flow_duration": "مدة الاتصال (ث)",
    "unique_dst_ports": "عدد المنافذ المقصودة",
    "syn_ratio": "نسبة حزم SYN",
    "failed_conn_ratio": "نسبة الاتصالات الفاشلة",
    "telnet_ratio": "نسبة اتصالات Telnet",
    "outbound_ratio": "نسبة البيانات الخارجة",
}

DEVICES = [
    {"name": "كاميرا البوابة الرئيسية", "type": "camera", "ip": "192.168.10.21"},
    {"name": "كاميرا موقف السيارات", "type": "camera", "ip": "192.168.10.22"},
    {"name": "كاميرا الممر الشرقي", "type": "camera", "ip": "192.168.10.23"},
    {"name": "منظّم حرارة المختبر", "type": "thermostat", "ip": "192.168.10.41"},
    {"name": "منظّم حرارة القاعة 3", "type": "thermostat", "ip": "192.168.10.42"},
    {"name": "منظّم حرارة المكتبة", "type": "thermostat", "ip": "192.168.10.43"},
    {"name": "منظّم حرارة غرفة الخوادم", "type": "thermostat", "ip": "192.168.10.44"},
    {"name": "مقبس الطابعة", "type": "smart_plug", "ip": "192.168.10.61"},
    {"name": "مقبس آلة القهوة", "type": "smart_plug", "ip": "192.168.10.62"},
    {"name": "مقبس المكيّف", "type": "smart_plug", "ip": "192.168.10.63"},
    {"name": "مقبس إضاءة الممر", "type": "smart_plug", "ip": "192.168.10.64"},
    {"name": "مقبس شاشة الاستقبال", "type": "smart_plug", "ip": "192.168.10.65"},
]


def profile(protocols, rate, size, duration, ports, syn, failed, telnet, outbound):
    return {"protocols": protocols, "rate": rate, "size": size, "duration": duration, "ports": ports,
            "syn": syn, "failed": failed, "telnet": telnet, "outbound": outbound}


NORMAL = {
    "camera": profile(["UDP", "TCP"], (150, 0.5), (900, 0.25), (60, 0.8), 0, (1, 30), (1, 50), (1, 300), (9, 1)),
    "thermostat": profile(["TCP"], (2, 0.7), (180, 0.35), (5, 0.7), 0, (2, 20), (1, 40), (1, 300), (5, 5)),
    "smart_plug": profile(["TCP", "UDP"], (5, 0.7), (120, 0.35), (3, 0.7), 0, (2, 20), (1, 40), (1, 300), (4, 6)),
}

ATTACKS = {
    "DDoS": (
        profile(["TCP", "UDP", "ICMP"], (3000, 0.6), (70, 0.2), (20, 0.6), 0, (8, 2), (5, 5), (1, 300), (19, 1)),
        profile(["TCP", "UDP"], (60, 0.7), (150, 0.4), (20, 0.6), 0, (3, 8), (2, 15), (1, 300), (8, 2)),
    ),
    "PortScan": (
        profile(["TCP"], (80, 0.6), (60, 0.15), (2, 0.6), 300, (9, 1), (8, 2), (1, 50), (6, 4)),
        profile(["TCP"], (6, 0.7), (100, 0.3), (3, 0.7), 3, (3, 10), (2, 12), (1, 100), (5, 5)),
    ),
    "BruteForce": (
        profile(["TCP"], (40, 0.5), (90, 0.3), (10, 0.7), 1, (4, 4), (7, 3), (8, 2), (5, 5)),
        profile(["TCP"], (5, 0.7), (120, 0.35), (4, 0.7), 0, (2, 15), (2, 15), (2, 20), (4, 6)),
    ),
    "Exfiltration": (
        profile(["TCP"], (60, 0.6), (700, 0.3), (30, 0.8), 0, (2, 20), (1, 40), (1, 300), (9, 1)),
        profile(["TCP"], (6, 0.7), (250, 0.35), (8, 0.8), 0, (2, 20), (1, 40), (1, 300), (7, 3)),
    ),
}


def sample_flows(rng, prof, n):
    rate = rng.lognormal(np.log(prof["rate"][0]), prof["rate"][1], n)
    size = rng.lognormal(np.log(prof["size"][0]), prof["size"][1], n)
    return pd.DataFrame({
        "protocol": rng.choice(prof["protocols"], n),
        "packet_rate": rate,
        "avg_packet_size": size,
        "byte_rate": rate * size,
        "flow_duration": rng.lognormal(np.log(prof["duration"][0]), prof["duration"][1], n),
        "unique_dst_ports": rng.poisson(prof["ports"], n) + 1,
        "syn_ratio": rng.beta(*prof["syn"], n),
        "failed_conn_ratio": rng.beta(*prof["failed"], n),
        "telnet_ratio": rng.beta(*prof["telnet"], n),
        "outbound_ratio": rng.beta(*prof["outbound"], n),
    })


def generate_dataset(n_normal=21000, n_attack=6000, seed=42, normal_label="Normal"):
    rng = np.random.default_rng(seed)
    parts = []
    for device in DEVICE_TYPES:
        part = sample_flows(rng, NORMAL[device], n_normal // len(DEVICE_TYPES))
        part.insert(0, "device_type", device)
        part["label"] = normal_label
        parts.append(part)
    per_attack = n_attack // len(ATTACK_TYPES)
    loud = int(per_attack * 0.7)
    for attack in ATTACK_TYPES:
        targets = ["thermostat", "smart_plug"] if attack == "Exfiltration" else DEVICE_TYPES
        for prof, n in zip(ATTACKS[attack], (loud, per_attack - loud)):
            part = sample_flows(rng, prof, n)
            part.insert(0, "device_type", rng.choice(targets, n))
            part["label"] = attack
            parts.append(part)
    data = pd.concat(parts, ignore_index=True)
    return data.sample(frac=1, random_state=seed).reset_index(drop=True)


def live_batch(rng, devices):
    rows = []
    for device in devices:
        attack = device["attack"]
        prof = NORMAL[device["type"]] if attack is None else ATTACKS[attack["kind"]][1 if attack["stealthy"] else 0]
        row = sample_flows(rng, prof, 1)
        row.insert(0, "device_type", device["type"])
        rows.append(row)
    return pd.concat(rows, ignore_index=True)
