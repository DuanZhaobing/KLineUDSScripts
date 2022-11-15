"""
**    Author:  DuanZhaobing                                                   **
**    e-mail:  duanzb@waythink.cn                                             **
**    Date:    22.09.27 - 22.11.15                                            **
**    Version: 1.0.0                                                          **
**    Project: KLine-SAIPA-Parameter                                          **
"""

AddressPara = {
    "Tgt": 0x59,  # Airbag controller address
    "Src": 0xF1  # Diagnostics address
}

FormatPara = {
    "fmt_80": 0x80,
    "fmt_81": 0x81
}

DiagnosticSidPara = {
    "StartCommunication": [0x81],  # 开始通信
    "StopCommunication": [0x82],  # 停止通信
    "DiagnosticSessionCustomer": [0x10],  # 诊断会话控制
    "ECUReset": [0x11],  # 软件复位
    "ClearFaultMemory": [0x14],  # 清除故障记录
    # "ReadFaultMemoryDTCAndTime": [0x17],  # 读故障码和时间
    "ReadFaultMemoryDTC": [0x18],  # 读故障码
    "ReadSDMIdentification": [0x1A],  # 读取SDM标识符
    "ReadDataByLocalIdentifier": [0x21],  # 通过标识符读取数据
    "ReadMemoryByAddress": [0x23],
    "SecurityAccess": [0x27],
    "TestPresent": [0x3e],  # 保持通讯
    "InputOutputControlByLocalIdentifier": [0x30],  # 通过本地标识符控制输入输出信号
    "WriteDataByLocalIdentifier": [0x3b],  # 通过标识符写入数据
    # "RequestDownload": [0x34],
    # "TransferData": [0x36],
    # "RequestTransferExit": [0x37]
    # "InputOutputControlByCommonIdentifier": [0x2f],  # 通过通用标识符控制输入输出信号
}

DiagnosticSessionCustomer = {
    "StandardDiagnosticSession": [0x81],
    "ExtendedDiagnosticSession": [0xFA]
}

ECUReset = {
    "HardwareReset": [0x01],
    "SoftwareReset": [0xFA]
}
StopCommunication = {

}

ReadFaultMemoryDTC = {
    "subfunc": [0x02],
    "parameter": [0xff, 0x00]
}
ReadFaultMemoryDTCAndTime = {
    "subfunc": [0x02],
    "parameter": [0xff, 0x00]
}

ECUResetService = {
    # "hardReset": [0x01]
}

ReadDTCInformationService = {
    "reportNumberOfDTCByStatusMask": [0x00, 0xff, 0x00],
    "reportNumberOfDTCByStatusMask_": [0x01, 0xff, 0x00]
}

SecurityAccess = {
    "RequestSeed": [0x01],
    "SendKey": [0x02, 0, 0]
}
TestPresent = {
}

ClearFaultMemory = {
    "allGroupDTC": [0xff, 0x00]
}
Temp = {

}

Temp_p = {
    "Para": [0]
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

ReadSDMIdentification = {
    "CustomerComponentID": [0x8A],
    "InternalPartNumber": [0x8B],
    "SystemSupplierPartNumber": [0x8c],
    "VehicleIdentificationNumber": [0x90],
    "OEMPartNumber": [0x91],
    "ProductionDate": [0x99],
    "ECUSoftwareVersion": [0x9c]
}

ReadDataByLocalIdentifier = {
    "UnitRealTimeData": [0x02],
    "SquibResistanceValue": [0x01],
    "CustomerSpecificData": [0x70],
    "EndOfLine": [0x78],
    "DataUnitRuntime": [0x80],
    "UnitIgnitionCycleCounter": [0x81],
    "UnitSerialNumber": [0x98],
    "ReadCrashRecordingDataBPTDeployment": [0x40],
    "ReadCrashRecordingDataFrontDeployment": [0x41],
    "ReadCrashRecordingDataRearDeployment": [0x42],
    "ReadCrashRecordingDataSideDriverDeployment": [0x43],
    "ReadCrashRecordingDataSidePassengerDeployment": [0x44]
}
WriteDataByLocalIdentifier = {
    "CustomerSpecificData": {
        "dataIdentifier": [0x70],
        "data": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    },
    "EndOfLine": {
        "dataIdentifier": [0x78],
        "data": [0x01]
    },
    "WriteVehicleIdentificationNumber": {
        "dataIdentifier": [0x90],
        "data": [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]
    },
    "ProductionDate": {
        "dataIdentifier": [0x99],
        "data": [0x20, 0x22, 0x11, 0x05]
    }
}

WriteDataByLocalIdentifierIniterinal = {
    "UnitSerialNumber": {
        "dataIdentifier": [0x8c],
        "data": [0x53, 0x36, 0x37, 0x37, 0x39, 0x4D, 0x30, 0x31, 0x31, 0x31, 0x32, 0x34, 0x35, 0x33, 0x00, 0x02, 0xE8,
                 0x01, 0x44, 0x02, 0x80, 0x01, 0x44, 0x02, 0x18, 0x01, 0x44, 0x02, 0xB0, 0x00, 0x44, 0x00]
    }
}

WriteDataByLocalIdentifierSub = {
}

InputOutputControlByIdentifier = {
    "AirbagWarningLamp": [0xd0, 0x00],  # 主驾安全气囊故障指示灯
    "PassengerAirbagDeactivationLamp": [0xd0, 0x01],  # 副驾安全气囊抑制指示灯
    "CrashOutput": [0xd0, 0x02],  # 碰撞输出
    "SeatBeltReminder": [0xd0, 0x03],  # 主驾安全带锁扣状态
    "PassengerAirbagActivationLamp": [0xd0, 0x04]  # 副驾安全气囊故障指示灯
}

InputOutputControlByLocalIdentifier = {
    "InputOutputControlOption": {
        "AirBagWarningLamp": [0x60],
        "PADLLamp": [0x61],
        "CrashOut": [0x62],
        "SeatBeltReminder": [0x63]
    },
    "InputOutputControlParameter": {
        "ReturnControlToECU": [0x00],
        "ReportCurrentState": [0x01],
        "ShortTimeAdjustment": [0x07],
    },
    "InputOutputControlState": {  # Only for ShortTimeAdjustment
        "Off": [0x00],
        "On": [0x01]
    }
}

InterinalService = {
    "Enable": [0x3B, 0x33, 0x01, 0x55],
    "ClearImpactData": [0x3B, 0x32, 0x02, 0x55],
    "CrashData1": [0x21, 0x14],
    "CrashData2": [0x21, 0x15],
    "CrashData3": [0x21, 0x16],
    "NearCrashData1": [0x21, 0x1B],
    "NearCrashData2": [0x21, 0x1C],
    "NearCrashData3": [0x21, 0x1D],
}

#########################################################
# NRC
NRCDefinition = {
    "serviceNotSupported": 0x11,  # Mnemonic SNS
    "subfunctionNotSupported": 0x12,  # Mnemonic SFNS
    "incorrectMessageLengthOrInvalidFormat": 0x13,  # Mnemonic IMLOIF
    "conditionsNotCorrect": 0x22,  # Mnemonic CNC
    "requestOutOfRange": 0x31,  # Mnemonic ROOR
    "securityAccessDenied": 0x33,  # Mnemonic SAD
    "invaledKey": 0x35,  # Mnemonic IK
    "exceedNumberOfAttempts": 0x36,  # Mnemonic ENOA
    "requiredTimeDelayNotExpired": 0x37,  # Mnemonic RTDNE
    "requestCorrectlyReceivedResponsePending": 0x78,  # Mnemonic RCRRP
    "serviceNotSupportedInActiveSession": 0x7f  # Mnemonic SFNSIAS
}
