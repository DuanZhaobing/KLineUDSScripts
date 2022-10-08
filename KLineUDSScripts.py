"""
**    Author:  DuanZhaobing                                                   **
**    e-mail:  duanzb@waythink.cn                                             **
**    Date:    22.09.27 - 22.10.08                                            **
**    Version: 0.0.0.1                                                        **
**    Project: KLine                                                          **
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
import serial
import time
from threading import Thread, Lock


# import WriteLog

class COM:
    def __init__(self, port, baud):
        self.port = port
        self.baud = int(baud)
        self.open_com = None
        # self.log = WriteLog.WriteLog('ITC_LOG.LOG')
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
            self.log.error('Open com fail:{}/{}'.format(self.port, self.baud))
            self.log.error('Exception:{}'.format(e))

    def close(self):
        if self.open_com is not None and self.open_com.isOpen:
            self.open_com.close()

    def send_data(self, data):
        if self.open_com is None:
            self.open()
        success_bytes = self.open_com.write(data.encode('UTF-8'))
        return success_bytes

    def get_data(self, over_time=300):
        all_data = ''
        if self.open_com is None:
            self.open()
        start_time = time.time()
        while True:
            end_time = time.time()
            if end_time - start_time < over_time and self.get_data_flag:
                if self.open_com.inWaiting():  # If the buffer has data, wait 0.05ms to avoid incomplete data reception.
                    time.sleep(0.05)
                    # data = self.open_com.read_all()  # Read all data in one timeout cycle
                    data = self.open_com.read(self.open_com.inWaiting())  # Read all data in the buffer
                    # data = self.open_com.read()  # read 1 size
                    data_str = " ".join('{:02X}'.format(a) for a in data)
                    if data_str != '':
                        # self.log.info('Get data is:{}'.format(data))
                        all_data = all_data + data_str
                        print(all_data)
                        # print(data)
                        self.real_time_data = all_data
            else:
                self.set_get_data_flag(True)
                break
        return all_data

    def get_device_version(self):
        self.send_data('VERSION')
        ver = self.get_data()
        device_version_str_ = ""
        for ascii_ in ver:
            device_version_str_ += str(chr(ascii_))
        print(device_version_str_)


if __name__ == '__main__':
    pass
    com = COM('com12', 912600)
    # com.open()
    com.get_device_version()
    # print(com.send_data('VERSION'))
    # com.send_data('data')
    # com.get_data(100)
    com.close()
