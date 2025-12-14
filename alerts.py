def send_alert(attack, req):
    print(f"[ALERT] {attack} from {req.remote_addr} on {req.path}")
