
import matplotlib.pyplot as plt
import json
import uuid
import ipaddress

from datetime import datetime
from collections import defaultdict
import os

# ===== CONFIGURATION =====
log_path = r"E:\PythonProjects\SecurityLogAnalyzerV2\security_log.txt"
project_folder = os.path.dirname(log_path)

# ===== INITIALIZE COUNTERS =====
successful_logins = 0
failed_logins = 0

failed_ips = defaultdict(int)
failed_users = defaultdict(int)
hourly_failed_logins = defaultdict(int)
failed_ip_events = defaultdict(list)

# ===== READ AND ANALYZE SECURITY LOG =====
try:
    print("DEBUG: Starting to read security log...")
    
    with open(log_path, "r", encoding="utf-8") as file:
        print("DEBUG: Security log file opend successfully.")

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            #Skip empty lines
            if not line:
                continue

            # Count successful logins
            if "Successful login" in line:
                successful_logins += 1

            # Analyze failed logins
            elif "Failed login" in line:
        
                # Validate timestamp
                try:
                    timestamp_text = line[:19].strip()
                    
                    timestamp = datetime.strptime(
                        
                        timestamp_text, "%Y-%m-%d %H:%M:%S"
                    )
                    
                except ValueError:
                    print(
                        f"WARNING: Invalid timestamp "
                        f"on line {line_number}"
                    )
                    continue
                #Extract and validate username
                try:
                    username = (
                        line.split(" - User: ", 1)[1]
                        .split(" - IP: ", 1)[0]
                        .strip()
                    )
                    if not username:
                        raise ValueError("Empty username")
                except (IndexError, ValueError):
                    print(
                        f"WARNING: Missing or invalid username"
                        f"on line {line_number}"
                    )
                    continue
                #Extract and validate IP address
                try:
                    ip_text = line.split(" - IP: ", 1)[1].strip()
                    
                    try:
                        valid_ip = ipaddress.ip_address(ip_text)
                    except ValueError:
                        print(f"WARNING: Invalid IP address:{ip_text}")
                        continue
                except ValueError:
                    print(
                        f"WARNING: Invalid IP address "
                        f"on line {line_number}"
                    )
                    continue

                #Count the valid failed login
                failed_logins += 1
                failed_users[username] += 1
                failed_ips[ip_text] += 1

                #Store timestamp for brute-force detection
                failed_ip_events[ip_text].append(timestamp)

                #Count failed logins by hour
                hour = timestamp.strftime("%H")
                hourly_failed_logins[hour] += 1

                #except FileNotFoundError:
                 #   print("ERROR: security_log.txt was not found.")
                  #  print("Check the log path:", log_path)
                
    # ===== BRUTE-FORCE DETECTION =====
    brute_force_alerts = []

    window_seconds = 120
    threshold = 5

    for ip, timestamps in failed_ip_events.items():

        sorted_times = sorted(timestamps)
        left = 0


        for right, current_time in enumerate(sorted_times):

            #Remove event outside the 2-minute window
            while (
                current_time - sorted_times[left]
            ).total_seconds() > window_seconds:
                left += 1

            attempts_in_window = right - left + 1

            #Flag 5 or more failures within 2 minutes
            if attempts_in_window >= threshold:

                brute_force_alerts.append({
                    "ip_address": ip,
                    "failed_attempts_in_window": attempts_in_window,
                    "window_seconds": window_seconds,
                    "window_start": sorted_times[left].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "window_end": current_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "reason":(
                        "5 or more failed login attempts "
                        "within 2 minutes"
                    )
                })

                #One alert per IP address
                break

    #Display brute-force detection results
    print("\n===== BRUTE-FORCE ATTACK DETECTION =====")

    if brute_force_alerts:
        for alert in brute_force_alerts:
            print("\nWARNING: Suspicious login pattern detected")
            print("IP Address:", alert["ip_address"])
            print(
                "Failed attempts in window",
                alert["failed_attempts_in_window"]
            )
            print("Window:", 
                  alert["window_start"],
                  "to", 
                  alert["window_end"])
            
            print("Reason:", alert["reason"])
    else:
        print("No brute_force patterns detected.")

    # ===== SECURITY SEVERITY =====
    total_logins = successful_logins + failed_logins

    if failed_logins >= 10:
        overall_severity = "CRITICAL"
    elif failed_logins >= 6:
        overall_severity = "HIGH"
    elif failed_logins >= 3:
        overall_severity = "MEDIUM"
    else:
        overall_severity = "LOW"

# ===== GENERATE SECURITY RECOMMENDATIONS =====
    if overall_severity == "CRITICAL":
        security_recommendations = [
            "Investigate the failed login activity immediately.",
            "Review suspicious IP addresses and their associated events.",
            "Check accounts with repeated failed login attempts.",
            "Review authentication logs for unusual activity.",
            "Verify whether any unauthorized access occurred."
        ]
    elif overall_severity == "HIGH":
        security_recommendations = [
            "Investigate repeated failed login attempts.",
            "Review suspicious IP addresses.",
            "Check accounts with repeated failures.",
            "Monitor authentication logs for further activity."
        ]
    elif overall_severity == "MEDIUM":
        security_recommendations =[
            "Monitor failed login attempts.",
            "Review unusual login patterns.",
            "Check accounts with repeated failures."
        ]
    else:
        security_recommendations =[
            "Continue routine security monitoring.",
            "Review authentication logs regularly."
        ]
    print("\n===== SECURITY RECOMMENDATION =====")

    for recommendation in security_recommendations:
        print("-" + recommendation)

    # ===== ACCOUNT ANALYSIS =====
    suspicious_users = {
        user: count
        for user, count in failed_users.items()
        if count >= 3
    }

    # ===== IP RISK ANALYSIS =====
    ip_analysis = []

    for ip, count in sorted(
        failed_ips.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        if count >= 10:
            risk = "HIGH"
            reason = "10 or more failed login attempts detected."
        elif count >= 5:
            risk = "MEDIUM"
            reason = "5 to 9 failed login attempts detected."
        else:
            risk = "LOW"
            reason = "1 to 4 failed login attempts detected."

        ip_analysis.append({
            "ip_address": ip,
            "failed_attempts": count,
            "risk_level": risk,
            "reason": reason
        })

    # Preserve the threshold of 3 for suspicious IPs
    suspicious_IPs = {
        item["ip_address"]: item["failed_attempts"]
        for item in ip_analysis
        if item["failed_attempts"] >= 3
    }

    # ===== DISPLAY IP ANALYSIS =====
    print("\n===== SUSPICIOUS IP ADDRESS ANALYSIS =====")

    if not ip_analysis:
        print("No failed login IP addresses found.")

    for item in ip_analysis:
        print(f"\nIP Address: {item['ip_address']}")
        print(f"Failed Attempts: {item['failed_attempts']}")
        print(f"Risk Level: {item['risk_level']}")
        print(f"Reason: {item['reason']}")

    # ===== DISPLAY ACCOUNT ANALYSIS =====
    print("\n===== ACCOUNT WITH REPEATED FAILURES =====")

    if suspicious_users:
        for user, count in suspicious_users.items():
            print(f"WARNING: user '{user}' - {count} failed attempts")
    else:
        print("No accounts exceeded the threshold.")

    # ===== DISPLAY TIME ANALYSIS =====
    print("\n===== TIME-BASED SECURITY ANALYSIS =====")

    if hourly_failed_logins:
        for hour in sorted(hourly_failed_logins):
            print(
                f"Hour {hour}: "
                f"{hourly_failed_logins[hour]} failed login attempts"
            )
    else:
        print("No valid failed-login timestamps found.")

    # ===== DISPLAY SUMMARY =====
    print("\n===== SECURITY LOG ANALYZER V2 =====")
    print("Successful logins:", successful_logins)
    print("Failed logins:", failed_logins)
    print("Total login attempts:", total_logins)
    print("Overall severity:", overall_severity)

    # ===== REPORT METADATA =====
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = "SEC-" + uuid.uuid4().hex[:8].upper()

    # ===== PREPARE JSON DATA =====
    security_data = {
        "report_id": report_id,
        "report_generated": report_time,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "total_login_attempts": total_logins,
        "overall_severity": overall_severity,
        "suspicious_ips": suspicious_IPs,
        "ip_analysis": ip_analysis,
        "suspicious_users": suspicious_users,
        "hourly_failed_logins": dict(hourly_failed_logins),
        "security_recommendations": security_recommendations,
        "brute_force_alerts": brute_force_alerts
    }

    # ===== SAVE JSON REPORT =====
    json_path = os.path.join(project_folder, "security_report.json")

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(security_data, json_file, indent=4)

    print("\nJSON report saved: security_report.json")

    # ===== SAVE TEXT REPORT =====
    txt_path = os.path.join(project_folder, "security_report.txt")

    with open(txt_path, "w", encoding="utf-8") as report:
        report.write("===== SECURITY LOG ANALYZER V2 =====\n")
        report.write(f"Report ID: {report_id}\n")
        report.write(f"Report generated: {report_time}\n\n")

        report.write("===== LOGIN SUMMARY =====\n")
        report.write(f"Successful logins: {successful_logins}\n")
        report.write(f"Failed logins: {failed_logins}\n")
        report.write(f"Total login attempts: {total_logins}\n\n")

        report.write("===== SECURITY ASSESSMENT =====\n")
        report.write(f"Overall severity: {overall_severity}\n\n")

        report.write("===== IP ADDRESS RISK ANALYSIS =====\n")

        if ip_analysis:
            for item in ip_analysis:
                report.write(f"\nIP Address: {item['ip_address']}\n")
                report.write(
                    f"Failed attempts: {item['failed_attempts']}\n"
                )
                report.write(f"Risk level: {item['risk_level']}\n")
                report.write(f"Reason: {item['reason']}\n")
        else:
            report.write("No failed login IP addresses found.\n")

        report.write("\n===== SUSPICIOUS USER ACCOUNTS =====\n")

        if suspicious_users:
            for user, count in suspicious_users.items():
                report.write(f"{user}: {count} failed attempts\n")
        else:
            report.write("None detected\n")

        report.write("\n===== TIME-BASED SECURITY ANALYSIS =====\n")

        if hourly_failed_logins:
            for hour in sorted(hourly_failed_logins):
                report.write(
                    f"Hour {hour}: {hourly_failed_logins[hour]} "
                    "failed login attempts\n"
                )
        else:
            report.write("No valid timestamps found.\n")
        report.write("\n===== SECURITY RECOMMENDATIONS =====\n")
        for recommendation in security_recommendations:
            report.write("-" + recommendation + "\n")
        
        report.write("\n===== BRUTE-FORCE ATTACK DETECTION =====\n")
        if brute_force_alerts:
            for alert in brute_force_alerts:
                report.write("\nWARNING: Suspicious login pattern detected\n")
                report.write(
                    f"IP Address:{alert['ip_address']}\n"
                )
                report.write(
                    "Failed attempts in window: "
                    f"{alert['failed_attempts_in_window']}\n"
                )

                report.write(
                    f"Window start: {alert['window_start']}\n"
                    )
                report.write(
                    f"Window end: {alert['window_end']}\\n"
                    )
                report.write(
                    f"Reason: {alert['reason']}\n"
                    )
        else:
            report.write("On brute-force patterns detected.\n")
        

    print("Security report saved: security_report.txt")
    print("Report ID:", report_id)

    # ===== CHART 1: LOGIN SUMMARY =====
    login_labels = ["Successful Logins", "Failed Logins"]
    login_values = [successful_logins, failed_logins]

    plt.figure(figsize=(9, 6))

    bars = plt.bar(
        login_labels,
        login_values,
        color=["#2E8B57", "#DC3545"],
        width=0.55,
        edgecolor="black",
        linewidth=0.7
    )

    #Display the number above each bar
    plt.bar_label(
        bars,
        padding=5,
        fontsize=11,
        fontweight="bold"
    )

    #Chart title and axis labbels

    plt.title(
        "Security Login Summary", 
        fontsize=16,
        fontweight="bold",
        pad=18
    )

    plt.xlabel("Login Type", fontsize=12, labelpad=10)
    plt.ylabel("Number of Attempts", fontsize=12, labelpad=10)

    #Set the vertical axis safely, even both counts are zero
    plt.ylim(0, max(login_values) + 3 if max(login_values) > 0 else 3)


    #Improve readability
    plt.grid(
        axis="y", 
        linestyle="--", 
        alpha=0.3
    )

    plt.gca().set_axisbelow(True)
    plt.tight_layout()

    #Save the chart in the project folder
    Dashboard_chart_path = os.path.join(
        project_folder,
        "security_dashboard.png"
    )

    plt.savefig(
        Dashboard_chart_path,
        dpi=150,
        bbox_inches="tight"
    )
    plt.close()

    print("Dashboard chart saved: security_dashboard.png")

    # ===== CHART 2: FAILED LOGINS BY IP =====
    if failed_ips:
        ip_labels = list(failed_ips.keys())
        ip_values = list(failed_ips.values())

        plt.figure(figsize=(10, 6))
        
        bars = plt.bar(
            ip_labels,
            ip_values,
            color="#4472C4",
            edgecolor="black",
            linewidth=0.6
        )

        plt.bar_label(
            bars,
            padding=4,
            fontsize=10,
            fontweight="bold"
        )
        plt.title(
            "Failed Login Attempts by IP Address",
            fontsize=15,
            fontweight="bold",
            pad=15
        )

        plt.xlabel("IP Address", fontsize=11, labelpad=10)
        plt.ylabel("Failed Login Attempt", fontsize=11, labelpad=10)

        plt.xticks(rotation=30, ha="right")
        plt.ylim(0, max(ip_values) + 3)
        
        plt.grid(axis="y", linestyle="--", alpha=0.3)
        plt.gca().set_axisbelow(True)
        plt.tight_layout()

        ip_chart_path = os.path.join(
            project_folder,
            "failed_logins_by_ip.png"
        )

        plt.savefig(
            ip_chart_path, 
            dpi=150,
            bbox_inches="tight"
        )

        plt.close()

        print("IP chart saved: failed_logins_by_ip.png")
    else:
        print("No failed login data available for the IP chart. ")


    print("\nReports saved: security_report.txt, security_report.json")

 
    # ===== CHART 3: IP RISK DISTRIBUTION =====

    risk_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }

    # Count IP addresses by risk level
    for item in ip_analysis:
        risk_level = item["risk_level"]

        if risk_level in risk_counts:
            risk_counts[risk_level] += 1

    risk_labels = list(risk_counts.keys())
    risk_values = list(risk_counts.values())

    plt.figure(figsize=(9, 6))

    bars = plt.bar(
        risk_labels,
        risk_values,
        color=["#2E8B57", "#F0AD4E", "#DC3545"],
        edgecolor="black",
        linewidth=0.7,
        width=0.6
    )

    # Display the number above each bar
    plt.bar_label(
        bars,
        padding=4,
        fontsize=11,
        fontweight="bold"
    )

    plt.title(
        "IP Risk Distribution",
        fontsize=16,
        fontweight="bold",
        pad=18
    )

    plt.xlabel("Risk Level", fontsize=12, labelpad=10)
    plt.ylabel("Number of IP Addresses", fontsize=12, labelpad=10)

    plt.ylim(
        0,
        max(risk_values) + 3 if max(risk_values) > 0 else 3
    )

    plt.grid(axis="y", linestyle="--", alpha=0.3)
    plt.gca().set_axisbelow(True)
    plt.tight_layout()

    risk_chart_path = os.path.join(
        project_folder,
        "ip_risk_distribution.png"
    )

    plt.savefig(
        risk_chart_path,
        dpi=150,
        bbox_inches="tight"
    )

    plt.close()

    print("Risk distribution chart saved: ip_risk_distribution.png")

# ===== CHART 4: FAILED ATTEMPTS BY RISK LEVEL =====

    

    # ===== CHART 4: FAILED ATTEMPTS BY RISK =====

    risk_attempts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }

    # Add failed attempts for each risk level
    for item in ip_analysis:
        risk_level = item["risk_level"]
        failed_count = item["failed_attempts"]

        if risk_level in risk_attempts:
            risk_attempts[risk_level] += failed_count

    risk_labels = list(risk_attempts.keys())
    risk_values = list(risk_attempts.values())

    plt.figure(figsize=(9, 6))

    bars = plt.bar(
        risk_labels,
        risk_values,
        color=["#2E8B57", "#F0AD4E", "#DC3545"],
        edgecolor="black",
        linewidth=0.7,
        width=0.6
    )

    # Display the total failed attempts above each bar
    plt.bar_label(
        bars,
        padding=4,
        fontsize=11,
        fontweight="bold"
    )

    plt.title(
        "Failed Login Attempts by IP Risk Level",
        fontsize=15,
        fontweight="bold",
        pad=18
    )

    plt.xlabel("IP Risk Level", fontsize=12, labelpad=10)
    plt.ylabel("Total Failed Login Attempts", fontsize=12, labelpad=10)

    plt.ylim(
        0,
        max(risk_values) + 3 if max(risk_values) > 0 else 3
    )

    plt.grid(axis="y", linestyle="--", alpha=0.3)
    plt.gca().set_axisbelow(True)
    plt.tight_layout()

    risk_attempts_chart_path = os.path.join(
        project_folder,
        "failed_attempts_by_risk.png"
    )

    plt.savefig(
        risk_attempts_chart_path,
        dpi=150,
        bbox_inches="tight"
    )

    plt.close()

    print("Risk attempts chart saved: failed_attempts_by_risk.png")

    print("IP risk chart saved: ip_risk_distribution.png")        
    
except FileNotFoundError:
    print("ERROR: security_log.txt was not found.")
    print("Check the log path:", log_path)
