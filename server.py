import socket
import requests
import re
import psutil
import GPUtil
import wmi
from scapy.all import sniff, IP
from collections import Counter
import threading
from flask import Flask, request, jsonify, Response, send_file, make_response
import time
from flask_cors import CORS
import win32gui
import win32ui
import win32con
from PIL import Image
import io
import base64



app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
CORS(app)
packet_data = []
whitelist = ["System Idle Process"]



#-----------------------------------------------------------------------------------------------
#IP정보파악
def get_private_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("ipconfig.kr", 443))
    private_ip =  sock.getsockname()[0]
    return private_ip

def get_public_ip():
    req = requests.get("http://ipconfig.kr")
    public_ip = re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', req.text)[1]
    return public_ip
#-----------------------------------------------------------------------------------------------



#-----------------------------------------------------------------------------------------------
#자원 사용량 resources_usage 내부에 저장됨
# MemoryType을 문자열로 변환하는 함수
def get_memory_type(type):
    memory_types = {
        0: "Unknown",
        24: "DDR3",
        26: "DDR4",
        # 추가적인 메모리 타입은 WMI 문서를 참조하여 매핑
    }
    return memory_types.get(type, "Other")

def get_ram_info_windows():
    try:
        w = wmi.WMI()
        ram_info = {
            'type': None,
            'speed': None,
            'slots_used': 0
        }
        for memory in w.Win32_PhysicalMemory():
            ram_info['type'] = get_memory_type(memory.MemoryType)  # 메모리 타입 변환
            ram_info['speed'] = memory.Speed
            ram_info['slots_used'] += 1  # 사용 중인 슬롯 수 계산
        return ram_info
    except Exception as e:
        print(e)
        return {}

def get_resources_usage():
    resources_usage = {}

    # CPU 사용량 및 사양 가져오기
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_cores = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq().current
    resources_usage['cpu'] = {'usage': cpu_usage, 'cores': cpu_cores, 'threads': cpu_threads, 'frequency': cpu_freq}

    # GPU 사용량 및 사양 가져오기
    gpus = GPUtil.getGPUs()
    gpu_usage = [gpu.load * 100 for gpu in gpus]
    gpu_specs = [{'name': gpu.name, 'total_memory': gpu.memoryTotal, 'temperature': gpu.temperature} for gpu in gpus]
    resources_usage['gpu'] = {'usage': gpu_usage, 'specs': gpu_specs}

    # RAM 사용량 및 사양 가져오기
    ram = psutil.virtual_memory()
    ram_usage = round(ram.used / (1024 ** 3),1)
    ram_total = round(ram.total / (1024 ** 3),1)
    
    # 추가 RAM 정보 가져오기
    ram_info = get_ram_info_windows()
    resources_usage['ram'] = {
        'usage': ram_usage,
        'total': ram_total,
        'type': ram_info.get('type', 'Unknown'),
        'speed': ram_info.get('speed', 'Unknown'),
        'slots_used': ram_info.get('slots', 'Unknown')
    }

    return resources_usage
#-----------------------------------------------------------------------------------------------



#-----------------------------------------------------------------------------------------------
#프로세스 트래픽 데이터
def get_processes_network_traffic(private_ip):
    def filter_remote_ip(conn):
        return conn.raddr and conn.raddr.ip not in ["127.0.0.1", private_ip]

    def get_process_connections(process):
        try:
            return {conn.raddr.ip for conn in process.connections() if filter_remote_ip(conn)}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return set()

    process_traffic = {}
    process_list = []  # 프로세스 이름을 저장할 리스트
    for process in psutil.process_iter(attrs=['name']):
        process_name = process.info['name']
        remote_ips = get_process_connections(process)
        if remote_ips:
            process_traffic[process_name] = remote_ips
            process_list.append(process_name)  # 프로세스 이름을 리스트에 추가

    return process_traffic, process_list
#-----------------------------------------------------------------------------------------------



# -----------------------------------------------------------------------------------------------
#프로세스 아이콘이미지
def get_icon_path(pid):
    try:
        process = psutil.Process(pid)
        exe_path = process.exe()
        return exe_path
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def get_icon(exe_path):
    large, small = win32gui.ExtractIconEx(exe_path, 0)
    win32gui.DestroyIcon(small[0])
    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
    hbmp = win32ui.CreateBitmap()
    hbmp.CreateCompatibleBitmap(hdc, 32, 32)
    hdc = hdc.CreateCompatibleDC()
    hdc.SelectObject(hbmp)
    hdc.DrawIcon((0, 0), large[0])

    bmpinfo = hbmp.GetInfo()
    bmpstr = hbmp.GetBitmapBits(True)
    img = Image.frombuffer(
        'RGB',
        (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
        bmpstr, 'raw', 'BGRX', 0, 1
    )
    win32gui.DestroyIcon(large[0])
    return img

def encode_image_to_base64(img):
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return base64.b64encode(img_io.getvalue()).decode('utf-8')
#-----------------------------------------------------------------------------------------------



#-----------------------------------------------------------------------------------------------
#패킷캡쳐 및 필터링
from collections import defaultdict, Counter
from scapy.all import sniff, IP
def packet_capture(private_ip):
    global whitelist
    global packet_data
    global packet_dict


    
    packet_data = []  # packet_data를 리스트로 초기화
    source_ips = defaultdict(Counter)  # Counter를 값으로 갖는 defaultdict 생성
    packet_sizes = defaultdict(int)  # int 값을 기본값으로 갖는 defaultdict 생성
    packet_dict = create_packet_dict(packet_data)
    
    
    try:
        while True:
            process_traffic, process_list = get_processes_network_traffic(private_ip)
            sniff(prn=lambda x: update_packet_data(x, private_ip, process_traffic, source_ips, packet_sizes), timeout=5, store=0)
    except Exception as e:
        print("Error occurred:", e)

def update_packet_data(packet, private_ip, process_traffic, source_ips, packet_sizes):
    process_traffic, process_list = get_processes_network_traffic(private_ip)
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if dst_ip == private_ip:
            source_ips[src_ip][dst_ip] += 1  # 출발지 IP 및 도착지 IP 별로 통신 횟수 증가
            packet_sizes[src_ip] += len(packet)  # 패킷의 실제 크기를 누적
            process_name = None
            process_icon = None
            for process, ips in process_traffic.items():
                if src_ip in ips:
                    process_name = process
                    if process_name in whitelist:
                        return
                    try:
                        pid = next((p.info['pid'] for p in psutil.process_iter(attrs=['pid', 'name']) if p.info['name'] == process_name), None)
                        if pid:
                            exe_path = get_icon_path(pid)
                            if exe_path:
                                img = get_icon(exe_path)
                                process_icon = encode_image_to_base64(img)
                    except Exception as e:
                        print(f"Error getting icon for process {process_name}: {e}")
                    break
            
            if process_name:
                new_data = f"{src_ip}, {source_ips[src_ip][dst_ip]}, {packet_sizes[src_ip]}, {process_name}, {process_icon}"
      
            else:
                new_data = f"{src_ip}, {source_ips[src_ip][dst_ip]}, {packet_sizes[src_ip]}, {src_ip}, {'OUT'}"
            
            # 기존 데이터에 있는지 확인하고 업데이트 또는 추가
            found = False

            for i, data in enumerate(packet_data):
                if data.startswith(f"{src_ip}"):
                    packet_data[i] = new_data
                    found = True
                    break

                parts = data.split(', ')
                if process_name and parts[3].strip().lower() == process_name.strip().lower():
                    # 기존 값에 신규 값을 더함
                    existing_ips = parts[0].split('/') + [src_ip]
                    unique_ips = '/'.join(sorted(set(existing_ips)))
                    combined_count = combined_count = int(parts[1]) + 1  # 통신 횟수 합산
                    combined_traffic = int(parts[2]) + packet_sizes.get(src_ip, 0)  # 트래픽량 합산
                    packet_data[i] = f"{unique_ips}, {combined_count}, {combined_traffic}, {process_name}, {process_icon}"
                    found = True
                    break  

            if not found:
                packet_data.append(new_data)
                
    packet_data.sort(key=lambda x: int(x.split(',')[2]), reverse=True)
    create_packet_dict(packet_data)
    return packet_data
#-----------------------------------------------------------------------------------------------



#-----------------------------------------------------------------------------------------------
from collections import defaultdict

packet_dict = defaultdict(lambda: {'packet_count': 0, 'packet_sizes': 0, 'risk_index': 0})
packet_dict_lock = threading.Lock()  # 쓰레드 간의 안전한 접근을 위한 Lock 객체 생성


def create_packet_dict(packet_data):
    global packet_dict
    with packet_dict_lock:
        packet_dict.clear()  # 기존 데이터를 모두 제거
        for data in packet_data:
            parts = data.split(', ')
            process_name = parts[3]
            packet_count = int(parts[1])
            packet_sizes = int(parts[2])
            packet_dict[process_name]['packet_count'] += packet_count
            packet_dict[process_name]['packet_sizes'] += packet_sizes
    return packet_dict


#-----------------------------------------------------------------------------------------------

#아래로 위험조치 코드

#-----------------------------------------------------------------------------------------------
import time
def update_risk_index():
    global packet_dict
    while True:
        time.sleep(10) 
        with packet_dict_lock:
            for process_name, data in packet_dict.items():
                packet_count_increase = data['packet_count']
                packet_size_increase = data['packet_sizes']
                if packet_count_increase >= 1 or packet_size_increase >= 10000:
                    packet_dict[process_name]['risk_index'] += 1
#-----------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------
import win32com.client
def add_block_rule(name, ip, direction):
    try:
        # WMI 객체 생성
        fw_policy2 = win32com.client.Dispatch('HNetCfg.FwPolicy2')

        # 현재 활성화된 모든 프로필을 가져옴
        currentProfiles = fw_policy2.CurrentProfileTypes

        # 새로운 규칙 객체 생성
        new_rule = win32com.client.Dispatch('HNetCfg.FWRule')
        new_rule.Name = name
        new_rule.RemoteAddresses = ip
        new_rule.Direction = 1 if direction.lower() == 'in' else 2  # Inbound = 1, Outbound = 2
        new_rule.Action = 0  # Block = 0
        new_rule.Enabled = True
        new_rule.Profiles = currentProfiles

        # 규칙을 방화벽에 추가
        fw_policy2.Rules.Add(new_rule)
        print(f'Successfully added the {direction}bound block rule for IP: {ip}')
    except Exception as e:
        print(f'Error adding the {direction}bound block rule for IP {ip}: {e}')
#-----------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------
def delete_firewall_rule(name):
    try:
        # WMI 객체 생성
        fw_policy2 = win32com.client.Dispatch('HNetCfg.FwPolicy2')

        # 방화벽 규칙들 가져오기
        rules = fw_policy2.Rules

        # 지정된 이름의 규칙 찾기 및 삭제
        rule_to_delete = None
        for rule in rules:
            if rule.Name == name:
                rule_to_delete = rule
                break
        
        if rule_to_delete:
            rules.Remove(rule_to_delete.Name)
            print(f'Successfully deleted the rule: {name}')
        else:
            print(f'No rule found with the name: {name}')
    except Exception as e:
        print(f'Error deleting the rule {name}: {e}')
#-----------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------
#json연결
@app.route('/data', methods=['GET'])
def get_data():
    private_ip = get_private_ip()
    public_ip = get_public_ip()
    resources_usage = get_resources_usage()
    process_traffic, process_list = get_processes_network_traffic(private_ip)
    risk = create_packet_dict(packet_data)
    white_list = whitelist


    # Convert process_traffic to a JSON serializable format
    process_traffic_serializable = {process: list(ips) for process, ips in process_traffic.items()}

    data = {
        'private_ip': private_ip,
        'public_ip': public_ip,
        'resources_usage': resources_usage,
        'process_list': process_list,
        'process_traffic': process_traffic_serializable,  # 수정된 부분
        'riskLV':risk,
        'whitelist':white_list,

        'packet_data': packet_data[:]  # 현재 packet_data의 복사본을 반환  
        
    }

    response = jsonify(data)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'

    return response


@app.route('/whitelist', methods=['POST'])
def add_to_whitelist():
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        whitelist.append(ip)
        return jsonify({'message': 'IP added to whitelist', 'whitelist': whitelist}), 200
    return jsonify({'error': 'Invalid data'}), 400


# @app.route('/firewall_policy', methods=['POST'])
# def add_to_fir    ewall_policy():
#     data = request.get_json()
#     ip = data.get('ip')
#     port = data.get('port')
#     if ip and port:
#         firewall_policies.append({'ip': ip, 'port': port})
#         return jsonify({'message': 'Firewall policy added', 'firewall_policies': firewall_policies}), 200
#     return jsonify({'error': 'Invalid data'}), 400



if __name__ == '__main__':
    private_ip = get_private_ip()
    # packet_capture 함수를 쓰레드로 실행하여 패킷 캡처
    packet_capture_thread = threading.Thread(target=packet_capture, args=(private_ip,))
    packet_capture_thread.start()

    update_risk_index_thread = threading.Thread(target=update_risk_index)
    update_risk_index_thread.start()

    app.run(debug=True)
