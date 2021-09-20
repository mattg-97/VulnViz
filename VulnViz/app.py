import csv
import os
import subprocess
import time
from flask import Flask, render_template, url_for, request

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def hello_world(name=None):
    return render_template('Visualize.html', name=name, func=url_for)


@app.route('/target/Nikto', methods=['GET', 'POST'])
def nikto_scan():
    if request.method == 'POST':
        req = request.form
        ip = req["ip"]
        ports = req["ports"]
    time.sleep(20)
    return render_template('nikto.html', ip=ip, ports=ports)


@app.route('/About')
def about():
    return render_template('about.html')


@app.route('/target', methods=['GET', 'POST'])
def target_dash():
    if request.method == 'POST':
        req = request.form
        id = req["ip_input"][:-1]
        portString = req["ports"][:-1]
        if "," in req["data"]:
            tempArray = req["data"][:-1].split(",")
        else:
            tempArray = [req["data"][:-1]]
        dataArray = [tempArray[i:i + 3] for i in range(0, len(tempArray), 3)]
        os.chdir("./scripts")
        cmd = f"nmap -sV -T4 --script vulners -p {portString} {id} -oX scanresults.xml"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)
        process.wait()
        os.chdir("./nmapvulners2csv")
        cmd2 = f"python nmapvulners2csv.py ../scanresults.xml"
        csv_process = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE)
        csv_process.wait()
        os.chdir("../../")
        myList = []
        with open("./scripts/nmapvulners2csv/output/output.csv", "r") as f:
            reader = csv.reader(f)
            for line in reader:
                if "id_vuln" not in line:
                    myList.append(line)
        return render_template('targetdash.html', ip=id, data=dataArray, ports=portString, list=myList)


if __name__ == '__main__':
    app.run()
