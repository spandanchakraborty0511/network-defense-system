from flask import Flask, render_template, jsonify
import sqlite3, json, os, datetime, subprocess, threading

app = Flask(__name__)

MODULE1_DB     = "../module1_arp_detection/arp_monitor.db"
MODULE2_DB     = "../module2_traffic_anomaly/traffic_anomaly.db"
MODULE8_ALERTS = "../module8_ids/ids_alerts.json"
MODULE3_JSON   = "../module3_rogue_ap/rogue_ap.json"
MODULE5_DIR    = "../module5_https_enforcement/"
MODULE7_LOG    = "../module7_vpn_protection/vpn_monitor_log.json"
CERT_BASELINE  = "../module5_https_enforcement/cert_baseline.json"

attack_logs      = []
attack_processes = {}

def get_arp_alerts():
    try:
        conn = sqlite3.connect(MODULE1_DB)
        c = conn.cursor()
        c.execute("SELECT timestamp,ip_address,old_mac,new_mac,alert_type FROM alerts ORDER BY timestamp DESC LIMIT 50")
        rows = c.fetchall(); conn.close()
        return [{"timestamp":r[0],"ip":r[1],"old_mac":r[2],"new_mac":r[3],"type":r[4],"module":"ARP Monitor","severity":"HIGH"} for r in rows]
    except: return []

def get_arp_devices():
    try:
        conn = sqlite3.connect(MODULE1_DB)
        c = conn.cursor()
        c.execute("SELECT ip_address,mac_address,first_seen,last_seen FROM arp_table")
        rows = c.fetchall(); conn.close()
        return [{"ip":r[0],"mac":r[1],"first_seen":r[2],"last_seen":r[3]} for r in rows]
    except: return []

def get_traffic_anomalies():
    try:
        conn = sqlite3.connect(MODULE2_DB)
        c = conn.cursor()
        c.execute("SELECT timestamp,anomaly_type,source_ip,details FROM anomalies ORDER BY timestamp DESC LIMIT 50")
        rows = c.fetchall(); conn.close()
        return [{"timestamp":r[0],"type":r[1],"ip":r[2],"details":r[3],"module":"Traffic Monitor","severity":"MEDIUM"} for r in rows]
    except: return []

def get_ids_alerts():
    try:
        if os.path.exists(MODULE8_ALERTS):
            with open(MODULE8_ALERTS) as f: alerts = json.load(f)
            return [{"timestamp":a["timestamp"],"type":a["rule"],"ip":a["src_ip"],
                     "details":a.get("details",""),"module":"IDS","severity":a.get("severity","MEDIUM").upper()}
                    for a in alerts[-50:]]
    except: pass
    return []

def get_rogue_ap_data():
    try:
        if os.path.exists(MODULE3_JSON):
            with open(MODULE3_JSON) as f: return json.load(f)
    except: pass
    return {"networks":[],"alerts":[],"stats":{}}

def is_module3_active():
    try:
        if not os.path.exists(MODULE3_JSON): return False
        age = (datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(MODULE3_JSON))).seconds
        return age < 120
    except: return False

def get_ssl_data():
    results = []
    try:
        if os.path.exists(CERT_BASELINE):
            with open(CERT_BASELINE) as f: baseline = json.load(f)
            for domain, info in baseline.items():
                days_left = info.get("days_until_expiry", info.get("days_left", -1))
                exp       = info.get("expiry_date", info.get("expiry", "Unknown"))
                issuer    = info.get("issuer", "Unknown")
                hsts      = info.get("hsts", False)
                valid     = info.get("valid", True)
                try:
                    if days_left == -1:
                        days_left = (datetime.datetime.strptime(exp,"%Y-%m-%d") - datetime.datetime.now()).days
                except: pass
                if not valid or days_left < 0: status = "EXPIRED"
                elif days_left < 14:           status = "EXPIRING_SOON"
                else:                          status = "OK"
                grade = "A" if status=="OK" else "B" if status=="EXPIRING_SOON" else "F"
                results.append({"domain":domain,"expiry":exp,"days_left":days_left,
                                 "issuer":issuer,"status":status,"hsts":hsts,"grade":grade})
    except: pass
    if not results:
        for d in ["github.com","google.com","facebook.com","wikipedia.org"]:
            results.append({"domain":d,"expiry":"Run ssl_monitor_final.py","days_left":-1,
                            "issuer":"Unknown","status":"UNKNOWN","hsts":False,"grade":"?"})
    return results

def get_vpn_alerts():
    alerts = []
    try:
        if not os.path.exists(MODULE7_LOG): return []
        with open(MODULE7_LOG) as f: log = json.load(f)
        for entry in log[-50:]:
            etype = entry.get("event","") or entry.get("event_type","")
            sev   = "HIGH" if etype in ("KILLSWITCH_ENABLED","VPN_DOWN") else                     "MEDIUM" if etype == "DNS_LEAK" else "LOW"
            alerts.append({
                "timestamp": entry.get("timestamp",""),
                "type":      etype,
                "ip":        "VPN",
                "details":   entry.get("details",""),
                "module":    "VPN Monitor",
                "severity":  sev
            })
    except: pass
    return alerts

def get_vpn_status():
    try:
        if not os.path.exists(MODULE7_LOG): return {"status":"UNKNOWN","details":"vpn_monitor_log.json not found"}
        with open(MODULE7_LOG) as f: log = json.load(f)
        if not log: return {"status":"UNKNOWN","details":"No events logged yet"}
        last = log[-1]
        et   = last.get("event","") or last.get("event_type","")
        ts   = last.get("timestamp","")
        det  = last.get("details","")
        if et == "KILLSWITCH_ENABLED": return {"status":"DOWN", "details":"Kill switch activated — "+det, "timestamp":ts}
        if et == "KILLSWITCH_DISABLED":return {"status":"UP",   "details":"Kill switch disabled — VPN restored", "timestamp":ts}
        if et == "DNS_LEAK":           return {"status":"DOWN", "details":"DNS Leak detected — "+det, "timestamp":ts}
        if et == "VPN_UP":             return {"status":"UP",   "details":det, "timestamp":ts}
        if et == "VPN_DOWN":           return {"status":"DOWN", "details":det, "timestamp":ts}
        return {"status":"UNKNOWN","details":f"Last event: {et}","timestamp":ts}
    except: return {"status":"UNKNOWN","details":"Error reading log"}

def get_blocked_ips():
    try:
        r = subprocess.run(["iptables","-L","INPUT","-n"],capture_output=True,text=True)
        blocked = []
        for line in r.stdout.split("\n"):
            if "DROP" in line and "all" in line:
                parts = line.split()
                if len(parts)>=4 and parts[3] not in ("0.0.0.0/0","anywhere"):
                    blocked.append(parts[3])
        return blocked
    except: return []

def get_system_stats():
    arp=get_arp_alerts(); traf=get_traffic_anomalies(); ids=get_ids_alerts()
    rogue=get_rogue_ap_data(); ra=rogue.get("alerts",[])
    total=len(arp)+len(traf)+len(ids)+len(ra)
    high=sum(1 for a in arp+ids+ra if a.get("severity")=="HIGH")
    locked=subprocess.run(["ip","neigh","show"],capture_output=True,text=True).stdout.count("PERMANENT")
    ssl=get_ssl_data(); ssl_ok=sum(1 for s in ssl if s["status"]=="OK")
    vpn_s = get_vpn_status()
    return {"total_alerts":total,"high_alerts":high,"locked_arp_entries":locked,"vpn_status":vpn_s.get("status","UNKNOWN"),
            "blocked_ips":len(get_blocked_ips()),"ssl_ok":ssl_ok,"ssl_total":len(ssl),
            "timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

def get_attack_timeline():
    all_alerts = get_arp_alerts()+get_traffic_anomalies()+get_ids_alerts()
    for a in get_rogue_ap_data().get("alerts",[]):
        all_alerts.append({"timestamp":a.get("timestamp",""),"severity":a.get("severity","LOW"),"type":a.get("type","ROGUE_AP")})
    now = datetime.datetime.now()
    hours = {}
    for i in range(24):
        t=(now-datetime.timedelta(hours=23-i)).strftime("%H:00")
        hours[t]={"HIGH":0,"MEDIUM":0,"LOW":0,"label":t}
    for a in all_alerts:
        try:
            key=datetime.datetime.strptime(a["timestamp"],"%Y-%m-%d %H:%M:%S").strftime("%H:00")
            sev=a.get("severity","LOW")
            if key in hours and sev in hours[key]: hours[key][sev]+=1
        except: pass
    return list(hours.values())

def run_command_async(cmd, name):
    attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":name,"status":"STARTED","output":f"Starting {name}..."})
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":name,"status":"COMPLETE","output":(r.stdout+r.stderr)[:500] or "Done"})
    except subprocess.TimeoutExpired:
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":name,"status":"TIMEOUT","output":"Timed out"})
    except Exception as e:
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":name,"status":"ERROR","output":str(e)})

@app.route("/")
def index(): return render_template("dashboard.html")

@app.after_request
def no_cache(r):
    r.headers['Cache-Control']='no-cache,no-store,must-revalidate'
    r.headers['Pragma']='no-cache'; r.headers['Expires']='0'; return r

@app.route("/api/alerts")
def api_alerts():
    arp     = get_arp_alerts()        # always HIGH
    traffic = get_traffic_anomalies()
    ids     = get_ids_alerts()
    vpn     = get_vpn_alerts()
    rogue_alerts = []
    for a in get_rogue_ap_data().get("alerts",[]):
        rogue_alerts.append({"timestamp":a.get("timestamp",""),"type":a.get("type","ROGUE_AP"),
                           "ip":a.get("bssid","N/A"),"module":"Rogue AP","severity":a.get("severity","MEDIUM")})
    # Always keep ALL high alerts, limit medium/low
    high_alerts = [a for a in arp+ids+rogue_alerts+vpn if a.get("severity")=="HIGH"]
    med_alerts  = [a for a in traffic+ids+rogue_alerts+vpn if a.get("severity")=="MEDIUM"]
    low_alerts  = [a for a in traffic+rogue_alerts+vpn if a.get("severity")=="LOW"]
    # Sort each group by timestamp newest first
    for lst in [high_alerts, med_alerts, low_alerts]:
        lst.sort(key=lambda x: x.get("timestamp",""), reverse=True)
    # Combine: all HIGH first, then MEDIUM, then LOW
    combined = high_alerts[:50] + med_alerts[:20] + low_alerts[:10]
    return jsonify(combined)

@app.route("/api/devices")
def api_devices(): return jsonify(get_arp_devices())

@app.route("/api/stats")
def api_stats(): return jsonify(get_system_stats())

@app.route("/api/blocked_ips")
def api_blocked(): return jsonify(get_blocked_ips())

@app.route("/api/ssl")
def api_ssl(): return jsonify(get_ssl_data())

@app.route("/api/vpn")
def api_vpn(): return jsonify(get_vpn_status())

@app.route("/api/timeline")
def api_timeline(): return jsonify(get_attack_timeline())

@app.route("/api/wifi_networks")
def api_wifi():
    d=get_rogue_ap_data()
    return jsonify({"networks":d.get("networks",[]),"stats":d.get("stats",{}),"last_update":d.get("last_update","Never")})

@app.route("/api/module_status")
def api_mod_status():
    return jsonify({
        "mod1":os.path.exists(MODULE1_DB),
        "mod2":os.path.exists(MODULE2_DB),
        "mod3":is_module3_active(),
        "mod4":True,
        "mod5":os.path.exists(CERT_BASELINE),
        "mod6":os.path.exists("../module6_cert_pinning/trusted_pins.json"),
        "mod7":os.path.exists("../module7_vpn_protection/keys.json"),
        "mod8":os.path.exists(MODULE8_ALERTS),
        "mod9":True,
        "mod10":os.path.exists("../module10_incident_response/incident_log.json"),
    })

@app.route("/api/block/<ip>")
def block_ip(ip):
    try:
        subprocess.run(["iptables","-A","INPUT","-s",ip,"-j","DROP"],capture_output=True)
        subprocess.run(["iptables","-A","OUTPUT","-d",ip,"-j","DROP"],capture_output=True)
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":"MANUAL_BLOCK","status":"COMPLETE","output":f"Blocked {ip}"})
        return jsonify({"status":"blocked","ip":ip})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

@app.route("/api/unblock/<ip>")
def unblock_ip(ip):
    try:
        subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"],capture_output=True)
        subprocess.run(["iptables","-D","OUTPUT","-d",ip,"-j","DROP"],capture_output=True)
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":"MANUAL_UNBLOCK","status":"COMPLETE","output":f"Unblocked {ip}"})
        return jsonify({"status":"unblocked","ip":ip})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

@app.route("/api/unblock_all")
def unblock_all():
    try:
        subprocess.run(["iptables","-F","INPUT"],capture_output=True)
        subprocess.run(["iptables","-F","OUTPUT"],capture_output=True)
        subprocess.run(["iptables","-P","INPUT","ACCEPT"],capture_output=True)
        subprocess.run(["iptables","-P","OUTPUT","ACCEPT"],capture_output=True)
        return jsonify({"status":"all_unblocked"})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

def write_vpn_log(event, details):
    try:
        log = []
        if os.path.exists(MODULE7_LOG):
            with open(MODULE7_LOG) as f: log = json.load(f)
        log.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event":event,"details":details})
        with open(MODULE7_LOG,"w") as f: json.dump(log,f,indent=4)
    except: pass

@app.route("/api/killswitch/enable")
def ks_on():
    try:
        for r in [["iptables","-A","OUTPUT","-o","lo","-j","ACCEPT"],
                  ["iptables","-A","OUTPUT","-o","wg0","-j","ACCEPT"],
                  ["iptables","-A","OUTPUT","-o","eth0","-p","udp","--dport","51820","-j","ACCEPT"],
                  ["iptables","-A","OUTPUT","-m","state","--state","ESTABLISHED,RELATED","-j","ACCEPT"],
                  ["iptables","-A","OUTPUT","-j","DROP"]]:
            subprocess.run(r,capture_output=True)
        write_vpn_log("KILLSWITCH_ENABLED","Manually enabled from dashboard")
        return jsonify({"status":"enabled"})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

@app.route("/api/killswitch/disable")
def ks_off():
    try:
        subprocess.run(["iptables","-F","OUTPUT"],capture_output=True)
        subprocess.run(["iptables","-P","OUTPUT","ACCEPT"],capture_output=True)
        write_vpn_log("KILLSWITCH_DISABLED","Manually disabled from dashboard")
        return jsonify({"status":"disabled"})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

@app.route("/api/killswitch/status")
def ks_status():
    try:
        r=subprocess.run(["iptables","-L","OUTPUT","-n"],capture_output=True,text=True)
        return jsonify({"active":"DROP" in r.stdout})
    except: return jsonify({"active":False})

@app.route("/api/attack/arp_spoof")
def atk_arp():
    try:
        if "arp_spoof" in attack_processes:
            try: attack_processes["arp_spoof"].terminate()
            except: pass
        p=subprocess.Popen(["arpspoof","-i","eth0","-t","192.168.137.1","192.168.137.2"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        attack_processes["arp_spoof"]=p
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":"ARP_SPOOF","status":"STARTED","output":"ARP spoofing started"})
        return jsonify({"status":"started","pid":p.pid})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

@app.route("/api/attack/stop_arp")
def atk_stop():
    try:
        if "arp_spoof" in attack_processes:
            attack_processes["arp_spoof"].terminate(); del attack_processes["arp_spoof"]
        subprocess.run(["pkill","-f","arpspoof"],capture_output=True)
        attack_logs.append({"timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"attack":"ARP_SPOOF","status":"STOPPED","output":"Stopped"})
        return jsonify({"status":"stopped"})
    except Exception as e: return jsonify({"status":"error","message":str(e)})

@app.route("/api/attack/port_scan")
def atk_scan():
    threading.Thread(target=run_command_async,args=(["nmap","-sS","192.168.137.1","--min-rate","1000","-p","1-100"],"PORT_SCAN"),daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/attack/icmp_flood")
def atk_icmp():
    threading.Thread(target=run_command_async,args=(["ping","192.168.137.1","-f","-c","200"],"ICMP_FLOOD"),daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/attack/ssl_check")
def atk_ssl():
    threading.Thread(target=run_command_async,args=(["python3","../module5_https_enforcement/https_checker_step1.py"],"SSL_CHECK"),daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/attack/logs")
def atk_logs(): return jsonify(attack_logs[-20:])

@app.route("/api/attack/clear")
def atk_clear(): attack_logs.clear(); return jsonify({"status":"cleared"})

@app.route("/api/attack/status")
def atk_status(): return jsonify({n:{"running":p.poll() is None,"pid":p.pid} for n,p in attack_processes.items()})

if __name__=="__main__":
    print("="*50)
    print("    NETDEFEND DASHBOARD v3.0")
    print("="*50)
    print("[*] http://127.0.0.1:5000")
    app.run(host="0.0.0.0",port=5000,debug=False,use_reloader=False)
