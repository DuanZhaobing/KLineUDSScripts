"""
**    Author:  DuanZhaobing                                                   **
**    e-mail:  duanzb@waythink.cn                                             **
**    Date:    22.09.27 - 22.11.15                                            **
**    Version: 1.0.0                                                          **
**    Project: KLine-SAIPA                                                    **
"""

"""
# !/usr/bin/python
# -*- coding: UTF-8 -*-
import threading

import pymysql
import serial
import serial.tools.list_ports
import time

SerialCfg = {
    "portName": {}
    , "baudRate": {}
    , "timeout": {}
}


def GetSerialPort():
    port_list = list(serial.tools.list_ports.comports())
    if len(port_list) <= 0:
        print("No serial device.")
    else:
        print("The serial port devices are as follows:")
        for comport in port_list:
            print(list(comport)[0], list(comport)[1])
    return port_list


if __name__ == "__main__":
    port_list = GetSerialPort()

    SerialCfg["portName"] = "COM3"  # 串口号
    SerialCfg["baudRate"] = 9600  # 波特率
    SerialCfg["timeout"] = 0.5  # 波特率
    # Open the serial port
    ser = serial.Serial(SerialCfg["portName"], SerialCfg["baudRate"], timeout=SerialCfg["timeout"])
"""
"""
# coding=gb18030
import threading
import time
import serial


class ComThread:
    def __init__(self, Port='COM3'):
        # 构造串口的属性
        self.l_serial = None
        self.alive = False
        self.waitEnd = None
        self.port = Port
        self.ID = None
        self.data = None

    # 定义串口等待的函数
    def waiting(self):
        if not self.waitEnd is None:
            self.waitEnd.wait()

    def SetStopEvent(self):
        if not self.waitEnd is None:
            self.waitEnd.set()
        self.alive = False
        self.stop()
        # 启动串口的函数

    def start(self):
        self.l_serial = serial.Serial()
        self.l_serial.port = self.port
        self.l_serial.baudrate = 115200
        # 设置等待时间，若超出这停止等待
        self.l_serial.timeout = 2
        self.l_serial.open()
        # 判断串口是否已经打开
        if self.l_serial.isOpen():
            self.waitEnd = threading.Event()
            self.alive = True
            self.thread_read = None
            self.thread_read = threading.Thread(target=self.FirstReader)
            self.thread_read.setDaemon(1)
            self.thread_read.start()
            return True
        else:
            return False

    def SendDate(self, i_msg, send):
        lmsg = ''
        isOK = False
        if isinstance(i_msg):
            lmsg = i_msg.encode('gb18030')
        else:
            lmsg = i_msg
        try:
            # 发送数据到相应的处理组件
            self.l_serial.write(send)
        except Exception as ex:
            pass;
        return isOK

    def FirstReader(self):
        while self.alive:
            time.sleep(0.1)

            data = ''
            data = data.encode('utf-8')

            n = self.l_serial.inWaiting()
            if n:
                data = data + self.l_serial.read(n)
                print('get data from serial port:', data)
                print(type(data))

            n = self.l_serial.inWaiting()
            if len(data) > 0 and n == 0:
                try:
                    temp = data.decode('gb18030')
                    print(type(temp))
                    print(temp)
                    car, temp = str(temp).split("\n", 1)
                    print(car, temp)

                    string = str(temp).strip().split(":")[1]
                    str_ID, str_data = str(string).split("*", 1)

                    print(str_ID)
                    print(str_data)
                    print(type(str_ID), type(str_data))

                    if str_data[-1] == '*':
                        break
                    else:
                        print(str_data[-1])
                        print('str_data[-1]!=*')
                except:
                    print("读卡错误，请重试！\n")

        self.ID = str_ID
        self.data = str_data[0:-1]
        self.waitEnd.set()
        self.alive = False

    def stop(self):
        self.alive = False
        self.thread_read.join()
        if self.l_serial.isOpen():
            self.l_serial.close()


# 调用串口，测试串口
def main():
    rt = ComThread()
    rt.sendport = '**1*80*'
    try:
        if rt.start():
            print(rt.l_serial.name)
            rt.waiting()
            print("The data is:%s,The Id is:%s" % (rt.data, rt.ID))
            rt.stop()
        else:
            pass
    except Exception as se:
        print(str(se))

    if rt.alive:
        rt.stop()

    print('')
    print('End OK .')
    temp_ID = rt.ID
    temp_data = rt.data
    del rt
    return temp_ID, temp_data


if __name__ == '__main__':
    # 设置一个主函数，用来运行窗口，便于若其他地方下需要调用串口是可以直接调用main函数
    ID, data = main()

    print("******")
    print(ID, data)
"""

"""
import serial  # 导入模块
import threading
import time
import logging
import sys


class UartInfo(object):
    def __init__(self, fd, count, fail):
        self.fd = fd
        self.count = count  # 测试次数
        self.fail = fail  # 失败次数

    response = False
    image_addr = 0x00
    image_crc = 0x00
    version = 0
    write_event = threading.Event()


uart = UartInfo(-1, 0, 0)


def logging_init():
    logging.basicConfig(  # filename="test.log", # 指定输出的文件
        level=logging.DEBUG,
        format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

    return True


# 十六进制显示
def hexShow(argv):
    try:
        result = ''
        hLen = len(argv)
        for i in range(hLen):
            hvol = argv[i]
            hhex = '%02x' % hvol
            result += hhex + ' '

        logging.info('Led Read:%s', result)
        return result
    except Exception as e:
        print("---异常---：", e)


def crc_sum(data, data_len):
    crc = 0
    i = 0
    while i < data_len:
        crc += data[i]
        i += 1
    return crc & 0x00FF


def crc_sum_u32(data, data_len):
    crc = 0
    i = 0
    while i < data_len:
        crc += data[i]
        i += 1
    return crc


# 打开串口
def DOpenPort(portx, bps, timeout):
    try:
        # 打开串口，并得到串口对象
        ser = serial.Serial(portx, bps, timeout=timeout)
        # 判断是否打开成功
        if False == ser.is_open:
            ser = -1
    except Exception as e:
        print("---异常---：", e)

    return ser


# 关闭串口
def DColsePort(ser):
    uart.fdstate = -1
    ser.close()


# 写数据
def DWritePort(ser, data):
    result = ser.write(data)  # 写数据
    logging.info(ser)
    logging.info("Led Write %s(%d)" % (data.hex(), result))
    return result


# 读数据
def ReadData_Thread(ser):
    # 循环接收数据，此为死循环，可用线程实现
    readstr = ""
    while -1 != ser:
        if ser.in_waiting:
            try:  # 如果读取的不是十六进制数据--
                readbuf = ser.read(ser.in_waiting)
                if readbuf[0] == 0x55 and readbuf[1] == 0xaa:
                    readstr = readbuf
                else:
                    readstr = readstr + readbuf

                hexShow(readstr)

                if (readstr[3] == 0x01) and (len(readstr) > 10):
                    uart.version = readstr[16]
                    uart.response = True
                    uart.write_event.set()
                elif (readstr[3] == 0x21) and (readstr[4] == 0x00) and (readstr[5] == 0x00):
                    uart.response = True
                    uart.write_event.set()
                elif (readstr[3] == 0x22) and (len(readstr) > 10):
                    uart.image_addr = (readstr[6] << 24 & 0xFF000000)
                    uart.image_addr += (readstr[7] << 16 & 0x00FF0000)
                    uart.image_addr += (readstr[8] << 8 & 0x0000FF00)
                    uart.image_addr += (readstr[9] << 0 & 0x000000FF)
                    uart.response = True
                    uart.write_event.set()
                elif (readstr[3] == 0x23) and (len(readstr) > 25):
                    uart.response = True
                    uart.write_event.set()

            except:  # --则将其作为字符串读取
                readbuf = ser.read(ser.in_waiting)
                hexShow(readbuf)


def GetVersion(ser):
    print("GetVersion")
    writebuf = bytearray([0x55, 0xaa, 0x00, 0x01, 0x00, 0x00])
    # crc
    writebuf.append(crc_sum(writebuf, len(writebuf)))
    DWritePort(ser, writebuf)

    logging.info("take")
    uart.response = False
    uart.write_event.clear()
    uart.write_event.wait(timeout=3)
    uart.write_event.clear()
    logging.info("give")
    if not uart.response:
        logging.info("fail")
        return False
    else:
        return True


# 测试任务
def Test_Thread(ser):
    while -1 != ser:
        uart.response = False
        uart.image_addr = 0x00
        uart.image_crc = 0x00
        uart.version = 0
        logging.info("count:%d", uart.count)
        logging.info("fail:%d", uart.fail)
        print("count", uart.count)
        print("fail", uart.fail)

        if GetVersion(ser):
            logging.info(uart.version)
            if uart.version == 0x37:
                otafile = "./UartV108.bin"
            else:
                otafile = "./UartV107.bin"
        else:
            uart.fail += 1
            uart.count += 1
            continue

        print("ota:", otafile)
        logging.info("ota:%s", otafile)
        time.sleep(2)

        uart.count += 1
        time.sleep(5)


def TestStop(ser):
    DColsePort(uart.fd)  # 关闭串口


if __name__ == "__main__":
    if 2 != len(sys.argv):
        print(len(sys.argv))
        print("please enter COM")
        exit()
    else:
        uart.tty = sys.argv[1]

    logging_init()
    uart.fd = DOpenPort(uart.tty, 115200, None)

    if uart.fd != -1:  # 判断串口是否成功打开
        threading.Thread(target=Test_Thread, args=(uart.fd,)).start()
        threading.Thread(target=ReadData_Thread, args=(uart.fd,)).start()
"""

# -*- encoding=utf-8 -*-
import threading
import serial
import time
from threading import Thread, Lock
from datetime import datetime
import KLineUDSPara as ParaDef
import logging
import copy

from datetime import datetime
from datetime import timedelta
from datetime import timezone

SHA_TZ = timezone(
    timedelta(hours=8),
    name='Asia/Shanghai',
)
serial_data_buf = ''  #
lock_com = Lock()  #

"""
logging.basicConfig(filename="logfile.log", level=logging.INFO)
# Log Creation

logging.info('your text goes here')
logging.error('your text goes here')
logging.debug('your text goes here')
"""


class COM(object):
    def __init__(self, port, baud):
        self.port = port
        self.baud = int(baud)
        self.open_com = None
        logging.basicConfig(filename="ReadFaultMemory.log",
                            filemode='a',
                            format='%(asctime)s,%(msecs)d - %(name)s - %(levelname)s - %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)  # or level=logging.INFO
        self.log = logging.getLogger(__name__)
        self.log.info('This is a log info')
        self.log.info('This is a log info')
        self.log.debug('Debugging')
        self.log.warning('Warning exists')
        self.log.info('Finish')
        self.get_data_flag = True
        self.real_time_data = ''

    # return real time data form com
    def get_real_time_data(self):
        return self.real_time_data

    def clear_real_time_data(self):
        self.real_time_data = ''

    # set flag to receive data or not
    def set_get_data_flag(self, get_data_flag):
        self.get_data_flag = get_data_flag

    def open(self):
        try:
            self.open_com = serial.Serial(self.port, self.baud)
        except Exception as e:
            # logging.error('Open com fail:{}/{}'.format(self.port, self.baud))
            # logging.error('Exception:{}'.format(e))
            self.log.error('Open com fail:{}/{}'.format(self.port, self.baud))
            self.log.error('Exception:{}'.format(e))

    def close(self):
        if self.open_com is not None and self.open_com.isOpen:
            self.open_com.close()

    def send_data(self, data):
        if self.open_com is None:
            self.open()
        self.get_data_flag = True
        success_bytes = self.open_com.write(data.encode('UTF-8'))
        time.sleep(0.300)
        global lock_com, serial_data_buf
        lock_com.acquire()
        receive_bytes = serial_data_buf
        print("Tx data: " + data)
        if receive_bytes != '':
            print("Rx data: " + receive_bytes)
        else:
            print("Timeout No Response!")
        lock_com.release()
        return success_bytes, receive_bytes

    def send_get_data(self, send_data, over_time):
        if self.open_com is None:
            self.open()
        self.get_data_flag = True
        # Calculate the checksum
        send_data_buf = send_data.copy()
        send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
        send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
        send_data_buf.insert(2, ParaDef.AddressPara["Src"])
        send_data_buf.insert(3, len(send_data_buf) - 3)
        checksum = 0
        for value in send_data_buf:
            checksum += value
        send_data_buf.append(checksum % 256)
        # Processing instructions
        send_data_str = 'DIAGNOSTIC'
        send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
        # 获取北京时间并格式化成22:24:24.000 形式
        beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
        current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
        # Write instructions to KLine diagnostic unit
        success_bytes = self.open_com.write(send_data_str.encode('UTF-8'))
        print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
        start_time = time.time()
        received_data_str = ''
        received_data = bytes()
        while self.get_data_flag:
            end_time = time.time()
            if end_time - start_time < over_time:
                if self.open_com.inWaiting():  # 若缓冲区存在数据
                    time.sleep(0.1)
                    received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                    data_str = " ".join('{:02X}'.format(a) for a in received_data)
                    if data_str != '':
                        received_data_str = received_data_str + data_str
                        self.real_time_data = received_data_str
            else:
                self.set_get_data_flag(False)
                break
        beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
        print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
        self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
        global lock_com, serial_data_buf
        lock_com.acquire()
        serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
        lock_com.release()
        time.sleep(0.1)
        return send_data_buf, received_data

    def start_send_receive_task(self, data, overtime):
        task = threading.Thread(target=COM.send_get_data, args=(self, data, overtime))
        # task.setDaemon(True)  # 把子线程设置为守护线程，必须在start()之前设置
        task.start()
        # task.join()

    def start_send_task(self, data):
        task = threading.Thread(target=COM.send_data, args=(self, data))
        # task.setDaemon(True)  # 把子线程设置为守护线程，必须在start()之前设置
        task.start()

    def get_device_version(self):
        self.send_data('VERSION')
        # ver = self.get_data()
        # device_version_str_ = ""
        # for ascii_ in ver:
        #     device_version_str_ += str(chr(ascii_))
        # print(device_version_str_)

    def start_communication(self, send_data, over_time):
        if self.open_com is None:
            self.open()
        self.get_data_flag = True
        # Calculate the checksum
        send_data_buf = send_data.copy()
        send_data_buf.insert(0, ParaDef.FormatPara["fmt_81"])
        send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
        send_data_buf.insert(2, ParaDef.AddressPara["Src"])
        checksum = 0
        for value in send_data_buf:
            checksum += value
        send_data_buf.append(checksum & 0xff)
        # Processing instructions
        send_data_str = 'DIAGNOSTIC'
        send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
        # 获取时间并格式化成22:24:24.000 形式
        beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
        current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
        # Write instructions to KLine diagnostic unit
        success_bytes = self.open_com.write(send_data_str.encode('UTF-8'))
        print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
        start_time = time.time()
        received_data_str = ''
        received_data = bytes()
        while self.get_data_flag:
            end_time = time.time()
            if end_time - start_time < over_time:
                if self.open_com.inWaiting():  # 若缓冲区存在数据
                    time.sleep(0.1)
                    received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                    data_str = " ".join('{:02X}'.format(a) for a in received_data)
                    if data_str != '':
                        received_data_str = received_data_str + data_str
                        self.real_time_data = received_data_str
            else:
                self.set_get_data_flag(False)
                break
        current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
        beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
        print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('gbk'))
        self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('gbk'))
        global lock_com, serial_data_buf
        lock_com.acquire()
        serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
        lock_com.release()
        time.sleep(0.1)
        return send_data_buf, received_data

    def uds_service_not_support(self, sid_list, data):
        if self.open_com is None:
            self.open()
        for sid_para in range(0, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = data.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            have_data_flag = False
            while sid_para in sid_list:
                sid_para += 1
            send_data_buf.insert(3, sid_para)
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)

    def uds_subfunction_not_support(self, sid, data_list):
        if self.open_com is None:
            self.open()
        for data_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            have_data_flag = False
            for value in data_list.values():
                if data_para in value:
                    have_data_flag = True
                    break
            if have_data_flag:
                have_data_flag = False
                continue
            send_data_buf.append(data_para)
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)

    def uds_subfunction_not_support_sec(self, sid, data_list):
        if self.open_com is None:
            self.open()
        for data_para in range(0x00, 0xff + 1):
            self.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                               + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            have_data_flag = False
            for value in data_list.values():
                if data_para in value:
                    have_data_flag = True
                    break
            if have_data_flag:
                have_data_flag = False
                continue
            send_data_buf.append(data_para)
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)

    def uds_subfunction_not_support_read_diagnostic(self, sid, subfunc, para):
        if self.open_com is None:
            self.open()
        for sub_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            send_data_buf.append(subfunc)
            if sub_para == subfunc[0]:
                sub_para += 1
            send_data_buf[4] = sub_para
            send_data_buf.append(para[0])
            send_data_buf.append(para[1])
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)

    def uds_subfunction_not_support_input_output_control(self, sid, subfunc, para, para_sta):
        if self.open_com is None:
            self.open()
        for sub_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            send_data_buf.append(subfunc)
            for value in subfunc.values():
                if sub_para in value:
                    sub_para += 1
            send_data_buf[4] = sub_para
            send_data_buf.append(para[0])
            if para_sta is not None:
                send_data_buf.append(para_sta[0])
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)

    def uds_subfunction_not_support_write_data_by_local_identifier(self, sid, data_list):
        if self.open_com is None:
            self.open()
        for data_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            have_data_flag = False
            for value in data_list.values():
                if data_para in value:
                    have_data_flag = True
                    break
            if have_data_flag:
                have_data_flag = False
                continue
            send_data_buf.append(data_para)
            send_data_buf.append(0)
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)

    def uds_request_out_of_range_read_diagnostic(self, sid, subfunc, para):
        if self.open_com is None:
            self.open()
        """
        """

        for sub_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            send_data_buf.append(subfunc[0])
            if sub_para is para[0]:
                continue
            send_data_buf.append(sub_para)
            send_data_buf.append(para[1])
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            time.sleep(0.1)
        for sub_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            # send_data_buf.insert(sid)
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            send_data_buf.append(subfunc[0])
            send_data_buf.append(para[0])
            if sub_para is para[1]:
                continue
            send_data_buf.append(sub_para)
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            time.sleep(0.1)

    def uds_request_out_of_range_clear_fault_memory(self, sid, data_list):
        if self.open_com is None:
            self.open()
        for data_para in range(0x00, 0xff + 1):
            self.get_data_flag = True  # Enable receive function
            send_data_buf = sid.copy()
            send_data_buf.insert(0, ParaDef.FormatPara["fmt_80"])
            send_data_buf.insert(1, ParaDef.AddressPara["Tgt"])
            send_data_buf.insert(2, ParaDef.AddressPara["Src"])
            # send_data_buf.insert(4, data_list.values()[0])
            # send_data_buf.insert(5, data_list.values()[1])
            have_data_flag = False
            for value in data_list.values():
                if data_para in value:
                    have_data_flag = True
                    break
            if have_data_flag:
                have_data_flag = False
                continue
            send_data_buf.append(0xff)
            send_data_buf.append(data_para)
            send_data_buf.insert(3, len(send_data_buf) - 3)
            # Calculate the checksum
            checksum = 0
            for value in send_data_buf:
                checksum += value
            send_data_buf.append(checksum & 0xff)
            # Processing instructions
            send_data_str = 'DIAGNOSTIC'
            send_data_str += "".join('{:02X}'.format(a) for a in send_data_buf)
            send_data_buf.clear()
            # 获取时间并格式化成22:24:24.000 形式
            beijing_now_tx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            current_time_send = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            # Write instructions to KLine diagnostic unit
            if self.open_com.write(send_data_str.encode('UTF-8')):
                print("Tx data: " + str(beijing_now_tx) + " " + send_data_str)
            else:
                print("Send error.")
            start_time = time.time()
            received_data_str = ''
            received_data = bytes()
            while self.get_data_flag:
                end_time = time.time()
                if end_time - start_time < 0.5:
                    if self.open_com.inWaiting():  # 若缓冲区存在数据
                        time.sleep(0.1)
                        received_data += self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                        data_str = " ".join('{:02X}'.format(a) for a in received_data)
                        if data_str != '':
                            received_data_str = received_data_str + data_str
                            self.real_time_data = received_data_str
                else:
                    self.set_get_data_flag(False)
                    break
            current_time_receive = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
            beijing_now_rx = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(SHA_TZ)
            print("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            self.log.info("Rx data: " + str(beijing_now_rx) + " " + received_data.decode('latin-1'))
            global lock_com, serial_data_buf
            lock_com.acquire()
            serial_data_buf = received_data_str  # 保存串口数据至全局变量缓存
            lock_com.release()
            time.sleep(0.1)


if __name__ == '__main__':
    try:
        pass
        # 获取时间并格式化成2016-8-28 22:24:24.000 形式
        current_time_start = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print("Start time:" + current_time_start)
        print('............')
        print('............\r\n')

        com = COM('com12', 912600)  # Open com

        com.start_communication(ParaDef.DiagnosticSidPara["StartCommunication"], 4)  # Start Communication

        """
        # Start Communication $81
        com.start_communication(ParaDef.DiagnosticSidPara["StartCommunication"], 4)  # Start Communication
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"]
                          + ParaDef.ReadFaultMemoryDTC["subfunc"] + ParaDef.ReadFaultMemoryDTC["parameter"], 0.5)  #
        """

        """
        # Stop Communication $82
        # time.sleep(3)
        # com.send_get_data(ParaDef.DiagnosticSidPara["StopCommunication"], 0.1)  #
        # com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"]
        #                   + ParaDef.ReadFaultMemoryDTC["subfunc"] + ParaDef.ReadFaultMemoryDTC["parameter"], 0.5)  #
        # com.start_communication(ParaDef.DiagnosticSidPara["StartCommunication"], 4)  # Start Communication
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["StopCommunication"],
                                        ParaDef.Temp)
        """

        """
        # DiagnosticSessionCustomer $10
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["StandardDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"],
                                        ParaDef.Temp)
        """


        """
        # ECUReset $11
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.log.info("Reset ECU.")
        print("Reset ECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["ECUReset"]
                          + ParaDef.ECUReset["HardwareReset"], 0.5)
        com.log.info("Check if Reset.")
        print("Check if Reset.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #

        com.log.info("Start Communication.")
        print("Start Communication.")
        com.start_communication(ParaDef.DiagnosticSidPara["StartCommunication"], 4)  # Start Communication
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["ECUReset"]
                          + ParaDef.ECUReset["SoftwareReset"], 0.5)
        com.log.info("Check if Reset.")
        print("Check if Reset.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #

        com.start_communication(ParaDef.DiagnosticSidPara["StartCommunication"], 4)  # Start Communication
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["ECUReset"], ParaDef.ECUReset)
        # NRC0x80
        com.send_get_data(ParaDef.DiagnosticSidPara["ECUReset"]
                          + ParaDef.ECUReset["HardwareReset"], 0.5)
        com.send_get_data(ParaDef.DiagnosticSidPara["ECUReset"]
                          + ParaDef.ECUReset["SoftwareReset"], 0.5)
        """

        """
        # 1Axx
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["CustomerComponentID"], 0.1)  # 0x8A
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["InternalPartNumber"], 0.1)  # 0x8B
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["SystemSupplierPartNumber"], 0.1)  # 0x8C
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["VehicleIdentificationNumber"], 0.1)  # 0x90
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["OEMPartNumber"], 0.1)  # 0x91
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["ProductionDate"], 0.1)  # 0x99
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["ECUSoftwareVersion"], 0.1)  # 0x9C
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["ReadSDMIdentification"],
                                        ParaDef.ReadSDMIdentification)
                                        
        # NRC13
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["CustomerComponentID"] + ParaDef.Temp_p["Para"], 0.1)  # 0x8A
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["InternalPartNumber"] + ParaDef.Temp_p["Para"], 0.1)  # 0x8B
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["SystemSupplierPartNumber"] + ParaDef.Temp_p["Para"], 0.1)  # 0x8C
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["VehicleIdentificationNumber"] + ParaDef.Temp_p["Para"], 0.1)  # 0x90
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["OEMPartNumber"] + ParaDef.Temp_p["Para"], 0.1)  # 0x91
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["ProductionDate"] + ParaDef.Temp_p["Para"], 0.1)  # 0x99
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadSDMIdentification"]
                          + ParaDef.ReadSDMIdentification["ECUSoftwareVersion"] + ParaDef.Temp_p["Para"], 0.1)  # 0x9C
        """

        """
        # 3Exx
        com.send_get_data(ParaDef.DiagnosticSidPara["TestPresent"], 0.1)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["TestPresent"],
                                        ParaDef.TestPresent)  #
        """

        """
        # 14 xx xx
        com.send_get_data(ParaDef.DiagnosticSidPara["ClearFaultMemory"]
                          + ParaDef.ClearFaultMemory["allGroupDTC"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["ClearFaultMemory"],
                                        ParaDef.Temp)  #
        com.uds_request_out_of_range_clear_fault_memory(ParaDef.DiagnosticSidPara["ClearFaultMemory"],
                                                        ParaDef.ClearFaultMemory)  #
        """

        """
        # 18 xx xx xx xx 
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"]
                          + ParaDef.ReadFaultMemoryDTC["subfunc"] + ParaDef.ReadFaultMemoryDTC["parameter"], 0.5)  #
        com.uds_subfunction_not_support_read_diagnostic(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"],
                                                        ParaDef.ReadFaultMemoryDTC["subfunc"],
                                                        ParaDef.ReadFaultMemoryDTC["parameter"])
        com.uds_request_out_of_range_read_diagnostic(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"],
                                                     ParaDef.ReadFaultMemoryDTC["subfunc"],
                                                     ParaDef.ReadFaultMemoryDTC["parameter"])
        """
        # com.send_get_data(ParaDef.DiagnosticSidPara["ClearFaultMemory"]
        #                   + ParaDef.ClearFaultMemory["allGroupDTC"], 0.5)  #
        # while True:
        #         #     com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"]
        #         #                       + ParaDef.ReadFaultMemoryDTC["subfunc"] + ParaDef.ReadFaultMemoryDTC["parameter"], 0.5)

        """
        # 17 xx xx xx xx 
        """
        # com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTCAndTime"]
        #                   + ParaDef.ReadFaultMemoryDTCAndTime["subfunc"]
        #                   + ParaDef.ReadFaultMemoryDTCAndTime["parameter"], 0.5)  #
        # com.uds_subfunction_not_support_read_diagnostic(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTCAndTime"],
        #                                                 ParaDef.ReadFaultMemoryDTCAndTime["subfunc"],
        #                                                 ParaDef.ReadFaultMemoryDTCAndTime["parameter"])
        # com.uds_request_out_of_range_read_diagnostic(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTCAndTime"],
        #                                              ParaDef.ReadFaultMemoryDTCAndTime["subfunc"],
        #                                              ParaDef.ReadFaultMemoryDTCAndTime["parameter"])

        """
        # 21 xx
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["UnitRealTimeData"], 0.5)  # 02
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["SquibResistanceValue"], 0.5)  # 01
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["CustomerSpecificData"], 0.5)  # 70
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["EndOfLine"], 0.5)  # 78
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["DataUnitRuntime"], 0.5)  # 80
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["UnitIgnitionCycleCounter"], 0.5)  # 81
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["UnitSerialNumber"], 0.5)  # 98
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["ReadCrashRecordingDataBPTDeployment"], 0.5)  # 40
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["ReadCrashRecordingDataFrontDeployment"], 0.5)  # 41
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["ReadCrashRecordingDataRearDeployment"], 0.5)  # 42
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["ReadCrashRecordingDataSideDriverDeployment"], 0.5)  # 43
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["ReadCrashRecordingDataSidePassengerDeployment"],
                          0.5)  # 44

        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"],
                                        ParaDef.ReadDataByLocalIdentifier)  #
        """

        """
        # 30 xx
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #

        # AirBagWarningLamp
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampReturnControlToECU.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"]["ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampReportCurrentState.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampReportCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"]["ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"]["ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"]["ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #

        # PADLLamp
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampCurrentState.")
        print("InputOutputControlByLocalIdentifier-PADLLampCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-PADLLampTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-PADLLampShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #
        # CrashOut
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        print("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        print("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #

        # SeatBeltReminder
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-SeatBeltReminder.")
        print("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        print("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #

        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.uds_subfunction_not_support_input_output_control(
            ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"],
            ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"],
            ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"]["ReturnControlToECU"], None)  #
        # MRC80
        # AirBagWarningLamp
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampReturnControlToECU.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampReportCurrentState.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampReportCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #

        # PADLLamp
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampCurrentState.")
        print("InputOutputControlByLocalIdentifier-PADLLampCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-PADLLampTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-PADLLampShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-PADLLampShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #
        # CrashOut
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        print("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        print("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #

        # SeatBeltReminder
        com.log.info("InputOutputControlByLocalIdentifier-SeatBeltReminder.")
        print("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReturnControlToECU"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        print("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ReportCurrentState"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        print("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
                          , 0.5)  #
        com.log.info("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        print("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["SeatBeltReminder"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
                              "ShortTimeAdjustment"]
                          + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
                          , 0.5)  #
        """

        # com.log.info("Switch to extended diagnostic session.")
        # print("Switch to extended diagnostic session.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
        #                   + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        #
        # # AirBagWarningLamp
        # com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampReturnControlToECU.")
        # print("InputOutputControlByLocalIdentifier-AirBagWarningLampReturnControlToECU.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ReturnControlToECU"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampReportCurrentState.")
        # print("InputOutputControlByLocalIdentifier-AirBagWarningLampReportCurrentState.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ReportCurrentState"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentOff.")
        # print("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentOff.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ShortTimeAdjustment"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentON.")
        # print("InputOutputControlByLocalIdentifier-AirBagWarningLampShortTimeAdjustmentON.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["AirBagWarningLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ShortTimeAdjustment"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
        #                   , 0.5)  #

        # PADLLamp
        # com.log.info("Switch to extended diagnostic session.")
        # print("Switch to extended diagnostic session.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
        #                   + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-PADLLampReturnControlToECU.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ReturnControlToECU"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-PADLLampCurrentState.")
        # print("InputOutputControlByLocalIdentifier-PADLLampCurrentState.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ReportCurrentState"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-PADLLampTimeAdjustmentOff.")
        # print("InputOutputControlByLocalIdentifier-PADLLampTimeAdjustmentOff.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ShortTimeAdjustment"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-PADLLampShortTimeAdjustmentON.")
        # print("InputOutputControlByLocalIdentifier-PADLLampShortTimeAdjustmentON.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["PADLLamp"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ShortTimeAdjustment"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
        #                   , 0.5)  #
        # CrashOut
        # com.log.info("Switch to extended diagnostic session.")
        # print("Switch to extended diagnostic session.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
        #                   + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        # print("InputOutputControlByLocalIdentifier-CrashOutReturnControlToECU.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ReturnControlToECU"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        # print("InputOutputControlByLocalIdentifier-CrashOutCurrentState.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ReportCurrentState"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        # print("InputOutputControlByLocalIdentifier-CrashOutTimeAdjustmentOff.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ShortTimeAdjustment"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["Off"]
        #                   , 0.5)  #
        # com.log.info("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        # print("InputOutputControlByLocalIdentifier-CrashOutShortTimeAdjustmentON.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["InputOutputControlByLocalIdentifier"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlOption"]["CrashOut"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlParameter"][
        #                       "ShortTimeAdjustment"]
        #                   + ParaDef.InputOutputControlByLocalIdentifier["InputOutputControlState"]["On"]
        #                   , 0.5)  #

        """
        0x27
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
                          + ParaDef.SecurityAccess["RequestSeed"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
                          + ParaDef.SecurityAccess["SendKey"], 0.5)  #
        com.uds_subfunction_not_support_sec(ParaDef.DiagnosticSidPara["SecurityAccess"], ParaDef.Temp)
        """

        """
        0x23
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
                          + ParaDef.SecurityAccess["RequestSeed"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["ReadMemoryByAddress"], ParaDef.Temp)
        """

        """
        0x3B
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        # com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
        #                   + ParaDef.SecurityAccess["RequestSeed"], 0.5)  #
        # com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
        #                   + ParaDef.SecurityAccess["SendKey"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["CustomerSpecificData"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["CustomerSpecificData"]["data"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["EndOfLine"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["EndOfLine"]["data"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["WriteVehicleIdentificationNumber"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["WriteVehicleIdentificationNumber"]["data"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["ProductionDate"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["ProductionDate"]["data"]
                          , 0.5)  #
        
        # NRC80
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["CustomerSpecificData"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["CustomerSpecificData"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["EndOfLine"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["EndOfLine"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["WriteVehicleIdentificationNumber"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["WriteVehicleIdentificationNumber"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["ProductionDate"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["ProductionDate"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        # NRC13
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["CustomerSpecificData"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["CustomerSpecificData"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["EndOfLine"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["EndOfLine"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["WriteVehicleIdentificationNumber"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["WriteVehicleIdentificationNumber"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["ProductionDate"]["dataIdentifier"]
                          + ParaDef.WriteDataByLocalIdentifier["ProductionDate"]["data"] + ParaDef.Temp_p["Para"]
                          , 0.5)  #
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.uds_subfunction_not_support_write_data_by_local_identifier(
            ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"],
            ParaDef.WriteDataByLocalIdentifierSub)
        """

        """
        0x34
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
                          + ParaDef.SecurityAccess["RequestSeed"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["RequestDownload"],
                                        ParaDef.Temp)
        """

        """
        0x36
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
                          + ParaDef.SecurityAccess["RequestSeed"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["TransferData"],
                                        ParaDef.Temp)

        """

        """
        0x37
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["SecurityAccess"]
                          + ParaDef.SecurityAccess["RequestSeed"], 0.5)  #
        com.uds_subfunction_not_support(ParaDef.DiagnosticSidPara["RequestTransferExit"],
                                        ParaDef.Temp)
        """

        """
        # NRC0x11
        com.uds_service_not_support(ParaDef.DiagnosticSidPara, [0x00])
        """

        """
        # Clear Impact Data
        com.log.info("Switch to extended diagnostic session.")
        print("Switch to extended diagnostic session.")
        com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
                          + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #

        com.send_get_data(ParaDef.InterinalService["Enable"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"]
                          + ParaDef.ReadFaultMemoryDTC["subfunc"] + ParaDef.ReadFaultMemoryDTC["parameter"], 0.5)

        com.send_get_data(ParaDef.InterinalService["ClearImpactData"], 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["ClearFaultMemory"]
                          + ParaDef.ClearFaultMemory["allGroupDTC"], 0.5)  #

        com.send_get_data(ParaDef.InterinalService["CrashData1"], 0.5)
        com.send_get_data(ParaDef.InterinalService["CrashData2"], 0.5)
        com.send_get_data(ParaDef.InterinalService["CrashData3"], 0.5)
        com.send_get_data(ParaDef.InterinalService["NearCrashData1"], 0.5)
        com.send_get_data(ParaDef.InterinalService["NearCrashData2"], 0.5)
        com.send_get_data(ParaDef.InterinalService["NearCrashData3"], 0.5)

        com.send_get_data(ParaDef.DiagnosticSidPara["ReadFaultMemoryDTC"]
                          + ParaDef.ReadFaultMemoryDTC["subfunc"] + ParaDef.ReadFaultMemoryDTC["parameter"], 0.5)

        com.send_get_data(ParaDef.DiagnosticSidPara["ECUReset"]
                          + ParaDef.ECUReset["HardwareReset"], 0.5)
        """

        # com.log.info("Switch to extended diagnostic session.")
        # print("Switch to extended diagnostic session.")
        # com.send_get_data(ParaDef.DiagnosticSidPara["DiagnosticSessionCustomer"]
        #                   + ParaDef.DiagnosticSessionCustomer["ExtendedDiagnosticSession"], 0.5)  #
        # com.send_get_data(ParaDef.InterinalService["Enable"], 0.5)  #
        # com.send_get_data(ParaDef.DiagnosticSidPara["WriteDataByLocalIdentifier"]
        #                   + ParaDef.WriteDataByLocalIdentifierIniterinal["UnitSerialNumber"]["dataIdentifier"]
        #                   + ParaDef.WriteDataByLocalIdentifierIniterinal["UnitSerialNumber"]["data"]
        #                   , 0.5)  #
        com.send_get_data(ParaDef.DiagnosticSidPara["ReadDataByLocalIdentifier"]
                          + ParaDef.ReadDataByLocalIdentifier["UnitSerialNumber"], 0.5)  #

        current_time_end = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print('............')
        print('............\r\n')
        print("End time:" + current_time_end)

    except KeyboardInterrupt:
        time.sleep(0.1)
        print('\nKeyboardInterrupt ...')
