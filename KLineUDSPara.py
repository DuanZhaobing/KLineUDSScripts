AddressPara = {
    "Tgt": 0x58,  # Airbag controller address
    "Src": 0xF1  # Diagnostics address
}
DiagnosticSidPara = {
    "StartCommunication": [0x81],  # 开始通信
    "StopCommunication": [0x82],  # 停止通信
    "DiagnosticSessionCustomer": [0x10],  # 诊断会话控制
    "TestPresent": [0x3e],  # 保持通讯
    "SoftReset": [0x11],  # 软件复位
    "ReadFaultMemoryDTC": [0x18],  # 读故障码
    "ClearFaultMemory": [0x14],  # 清除故障记录
    "ReadDataByLocalIdentifier": [0x21],  # 通过标识符读取数据
    "WriteDataByLocalIdentifier": [0x3b],  # 通过标识符写入数据
    "InputOutputControlByCommonIdentifier": [0x2f],  # 通过标识符控制输入输出信号
}

StartDiagnosticSession = {
    "customer": [0x81],
    "production": [0x83],
    "development": [0x85]
}

ECUResetService = {
    "hardReset": [0x01]
}

ReadDTCInformationService = {
    "reportNumberOfDTCByStatusMask": [0x00, 0xff, 0x00],
    "reportNumberOfDTCByStatusMask_": [0x01, 0xff, 0x00]
}

ClearDiagnosticInformationService = {
    "allGroupDTC": [0x00]
}

ReadDataByIdentifierService = {
    "ReadSystemIdentification": [0x80],  # 读系统信息
    "ReadECUManufacturingDate": [0x8b],  # 读ECU生产日期
    "ReadECUSerialNumber": [0x8c],  # 电控单元零件号
    "ReadVehicleIdentificationNumber": [0x90],  # 车辆底盘号
    "ReadCrashDataFrontCrash1": [0xd1],  # 读取气囊前向Crash数据1
    "ReadCrashDataFrontCrash2": [0xd2],  # 读取气囊前向Crash数据2
    "ReadCrashDataFrontCrash3": [0xd3],  # 读取气囊前向Crash数据3
    "ReadCrashDataFrontCrash4": [0xd4],  # 读取气囊前向Crash数据4
    "ReadCrashDataFrontCrash5": [0xd5],  # 读取气囊前向Crash数据5
    "ReadCrashDataFrontCrash6": [0xd6],  # 读取气囊前向Crash数据6
    "ReadCrashDataFrontCrash7": [0xd7],  # 读取气囊前向Crash数据7
    "ReadCrashDataFrontNearCrash8": [0xd8],  # 读取气囊前向NearCrash数据8
    "ReadCrashDataFrontNearCrash9": [0xd9],  # 读取气囊前向NearCrash数据9
    "ReadCrashDataFrontNearCrash10": [0xda],  # 读取气囊前向NearCrash数据10
    "ReadCrashDataFrontNearCrash11": [0xdb],  # 读取气囊前向NearCrash数据11
    "ReadCrashDataFrontNearCrash12": [0xdc],  # 读取气囊前向NearCrash数据12
    "ReadCrashDataFrontNearCrash13": [0xdd],  # 读取气囊前向NearCrash数据13
    "ReadCrashDataFrontNearCrash14": [0xde],  # 读取气囊前向NearCrash数据14
}

WriteDataByIdentifierService = {
    "WriteECUManufacturingDate": {
        "dataIdentifier": [0x8b],
        "data": [0x20, 0x22, 0x10, 0x20]
    },
    "WriteECUSerialNumber": {
        "dataIdentifier": [0x8c],
        "data": [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]
    },
    "WriteVehicleIdentificationNumber": {
        "dataIdentifier": [0x90],
        "data": [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]
    }
}

InputOutputControlByIdentifier = {
    "AirbagWarningLamp": [0xd0, 0x00],  # 主驾安全气囊故障指示灯
    "PassengerAirbagDeactivationLamp": [0xd0, 0x01],  # 副驾安全气囊抑制指示灯
    "CrashOutput": [0xd0, 0x02],  # 碰撞输出
    "SeatBeltReminder": [0xd0, 0x03],  # 主驾安全带锁扣状态
    "PassengerAirbagActivationLamp": [0xd0, 0x04]  # 副驾安全气囊故障指示灯
}
