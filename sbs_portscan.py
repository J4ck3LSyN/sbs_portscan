import socket,time,subprocess,sys,string

class portScanner:
    def __init__(self):
        self.configure = {
            'root.target'   :None, # Target
            'root.portMin'  :0, # Minimum Port
            'root.portMax'  :1000, # Maximum Port
            'root.timeOut'  :0.0001, # Timeout Float
            'root.sleep'    :0, # Sleep If NEeded
            'root.platForm' :sys.platform, # Platform (Win/Linux)
            'root.srcPort'  :[21,22,80,8080,135,443,445,9001,9999],

            'nmap.oN'       :None,  # -oN
            'nmap.sV'       :True,  # -sV
            'nmap.sC'       :True,  # -sC
            'nmap.T5'       :True,  # -T5
            'nmap.ports'    :[],    # -p
            'nmap.O'        :False, # -O
            'nmap.All'      :False, # -A
            'nmap.verbose'  :False, # -vv
            'nmap.pN'       :False, # -Pn
            'nmap.sU'       :False, # -sU

            'display.banner':[
                f'''
                        .---------------------------.
                       /,--..---..---..---..---..--. `.
                      //___||___||___||___||___||___\_|
                      [j__ ######################## [_|
                         \============================|
                      .==|  |"""||"""||"""||"""| |"""||
                     /======"---""---""---""---"=|  =||
                     |_____ShortBusSecurity____  | ==||
                     //  \\               //  \\ |===||=>.....
                     "\__/"---------------"\__/"-+---+'
____________________________________________________________________________
Author:J4ck3LSyN
----------------------------------------------------------------------------
                ''',
            ],    # Banner
            'display.menu0init':[
                '\t[00] Run',
                '\t[01] Configure',
                '\t[99] Exit'
            ], # Menu0 Interactive (Set Target)
            'display.menu1init':[
                '\t[00] Configure Item Key'
                '\t[99] Return To Main Screen'
            ],  # Menu1 Interactive (Configure)
            'display.usageArgV':[
                'python portScanner.py <target-IP> [ARGS]',
                '\tArguments:',
                '\t\t-cC, --customConfig',
                '\t\t\tTakes 1 Input `-cC:<Custom-Config-Object>`',
                '\t\t\t--- minimal, Minimal, MINIMAL',
                '\t\t\t---^ Runs Based Off Current Configuration',
                '\t\t\t--- source, Source, SOURCE',
                '\t\t\t---^ Only Runs Source Ports'
            ], # Sys.argv Usage

            'interactive.mode':0,
            'interactive.status':False,
            'interactive.KeyboardInterruptCount':0,
            'interactive.KeyboardInterruptMax':5,
            'interactive.displayAllPorts':False,
            'interactive.displayFoundPorts':True,
            'interactive.displayConfigBeforeOp':False,
            'interactive.runNmapPostOp':True
        }

    # IP Target Validation
    def validateTargetIP(self,target):
        if str('.') in str(target):
            tS = target.split('.')
            if len(tS) == 4:
                validOctet = True
                for tO in tS:
                    if len(str(tO)) <= 3:
                        continue
                    else:
                        validOctet = False;break
                if validOctet == True:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    ### Socket Functiions ###
    # Scan Through Ports
    def socketScan(self):
        if self.configure['root.target'] != None:
            print(f'Target: {str(self.configure["root.target"])}')
            targetPorts = []
            if len(self.configure['root.srcPort']) != 0:
                print(f'Source Ports: {str(" ".join([ str(i) for i in self.configure["root.srcPort"] ]))}')
                for port in self.configure['root.srcPort']:
                    targetPorts.append(int(port))
            if int(self.configure['root.portMin']) < int(self.configure['root.portMax']):
                for port in range(int(self.configure['root.portMin']),int(self.configure['root.portMax'])):
                    if int(port) not in targetPorts:
                        targetPorts.append(port)
            for portIter in targetPorts:
                socketObject = self.socketBuildTCP()
                socketObject = self.socketSetTimeout(socketObject)
                socketObject = self.socketConnectEx(socketObject,int(portIter))
                if self.configure['root.sleep'] != 0:
                    time.sleep(self.configure['root.sleep'])
                if self.configure['interactive.displayAllPorts'] == True:
                    print(f'{str(self.configure["root.target"])}:{str(socketObject[0])} -> Status: {str(socketObject[1])} Port Count: {str(len(self.configure["nmap.ports"]))} Max Port: {str(self.configure["root.portMax"])}')
                if socketObject[1] == True:
                    if self.configure['interactive.displayFoundPorts'] == True:
                        print(f'Found Port: {str(socketObject[0])}')
                    self.configure['nmap.ports'].append(int(socketObject[0]))
        else:
            self.exceptionHandle('socketScan()','Target Is Not Configured')
    # connect_ex
    def socketConnectEx(self,socketObject,port):
        if self.configure['root.target'] != None:
            try:
                portValue = socketObject.connect_ex((str(self.configure['root.target']),int(port)))
                if portValue == 0:
                    return [int(port),True]
                else:
                    return [int(port),False]
            except Exception as E:
                self.exceptionHandle(f'socketConnectEx({str(socketObject)},{str(port)})',f'Internal Socket Exception: {E}')
        else:
            self.exceptionHandle(f'socketConnectEx({str(socketObject)},{str(port)})')

    # Set Timeout
    def socketSetTimeout(self,socketObject):
        try:
            socketObject.settimeout(float(self.configure['root.timeOut']))
            return socketObject
        except Exception as E:
            self.exceptionHandle(f'socketSetTimeout({str(socketObject)})',f'Internal Socket Exception: {E}')
    # Build Socket Object (Per Request)
    def socketBuildTCP(self):
        return socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ### Display ###
    # Clear Screen
    def displayClearScreen(self):
        if str('win') in str(self.configure['root.platForm']):
            subprocess.run(['cls'],shell=True)
        else:
            subprocess.run(['clear'],shell=True)

    # Display Key
    def displayScreenKey(self,key):
        if str(key) in self.configure and str('display') in str(key):
            for line in self.configure[str(key)]:
                print(str(line))
        else:
            self.exceptionHandle(f'displayScreenKey({str(key)})','Key In Invalid Or Not Display Key')
    # Display Configure Variable
    def displayConfigure(self):
        for key in self.configure:
            if str('display') not in str(key):
                message = f'Key[{str(key)}]:{str(type(self.configure[str(key)]))} : {str(self.configure[key])}';print(str(message))
    # Interactive Menu
    def displayInteractive(self):
        self.configure['interactive.mode'] = 0;self.configure['interactive.status'] = True;
        while self.configure['interactive.status'] == True:
            try:
                if self.configure['interactive.mode'] == 0:
                    self.displayScreenKey('display.menu0init')
                elif self.configure['interactive.mode'] == 1:
                    self.displayScreenKey('display.menu1init')
                if self.configure['interactive.mode'] == 0:
                    userInput = input('[Root]:>> ')
                    if userInput in ['99','exit']:
                        self.configure['interactive.status'] = False
                    elif userInput in ['00','0','exec']:
                        if self.configure['root.target'] == None:
                            targetInput = input('[Target]:>> ')
                        else:
                            targetInput = str(self.configure['root.target'])
                        if self.validateTargetIP(str(targetInput)) == True:
                            self.configure['root.target']=str(targetInput)
                            if self.configure['interactive.displayConfigBeforeOp'] == True:
                                self.displayConfigure()
                            self.socketScan()
                            if len(self.configure['nmap.ports']) != 0:
                                print(f'Found Ports: {str(self.configure["nmap.ports"])}\nBuilding Nmap Command')
                                commandList = self.buildNmapCommand()
                                self.commandListToExecStr(commandList)
                                if self.configure['interactive.runNmapPostOp'] == True:
                                    process = self.subprocessBuildProcess(commandList)
                                    print(f'Processing {str(commandList)}')
                                    output  = self.subprocessCommunicate(process)
                                    print(f'Command Output:\n{str(output[0].decode("utf-8"))}')

                            else:
                                print(f'No TCP Ports Found On Target: {targetInput}')
                                commandList = self.buildNmapCommand()
                                self.commandListToExecStr(commandList)
                        else:
                            print(f'Target: {targetInput} Is Invalid')
                            continue
                    elif userInput in ['01','1','configure']:
                        self.configure['interactive.mode'] = 1
                    else:
                        print(f'Invalid Entry: {userInput}')
                elif self.configure['interactive.mode'] == 1:
                    self.displayConfigure()
                    userInput = input('[Configure]:>> ')
                    if userInput in ['99','return']:
                        self.configure['interactive.mode'] = 0
                    else:
                        if userInput in self.configure and str('display') not in str(userInput):
                            entryInput = input(f'[{str(userInput)}]:>> ')
                            if isinstance(self.configure[str(userInput)],str) == True or userInput in ['root.target','nmap.oN']:
                                self.configure[str(userInput)] = str(entryInput)
                                print(f'Configured {str(userInput)} To {str(entryInput)}')
                            elif isinstance(self.configure[str(userInput)],bool) == True:
                                if entryInput in ['00','0','false','False','FALSE']:
                                    self.configure[str(userInput)] = False
                                    print(f'Configured {str(userInput)} To False')
                                elif entryInput in ['01','1','true','True','TRUE']:
                                    self.configure[str(userInput)] = True
                                    print(f'Configured {str(userInput)} To True')
                                else:
                                    print('Boolean Values Must Be\n[ 00,0,false,False,FALSE ] To Be False\n[ 01,1,true,True,TRUE ] To Be True')
                            elif isinstance(self.configure[str(userInput)],int) == True:
                                isInteger = True
                                for char in str(entryInput):
                                    if str(char) not in string.digits:
                                        isInteger = False;break
                                if isInteger == True:
                                    self.configure[str(userInput)] = int(entryInput)
                                    print(f'Configured {userInput} To {str(entryInput)}')
                                else:
                                    print(f'Entry Carried Characters That Where Not Digits, {entryInput}')
                            elif isinstance(self.configure[str(userInput)],list) == True:
                                if str(', ') in str(entryInput):
                                    entryInput = entryInput.split(' ')
                                elif str(',') in str(entryInput):
                                    entryInput = entryInput.split(',')
                                else:
                                    entryInput = [entryInput]
                                self.configure[userInput] = entryInput
                                print(f'Configured {userInput} To {str(entryInput)}')
                            elif isinstance(self.configure[str(userInput)],float) == True:
                                isFloat = True
                                if str('.') in str(entryInput):
                                    eO = entryInput.split('.')
                                    for char in str(eo[0]):
                                        if str(char) not in string.digits:
                                            isFloat = False;break
                                    for char in str(eo[1]):
                                        if str(char) not in string.digits:
                                            isFloat = False;break
                                else:
                                    isFloat = False
                                if isFloat == True:
                                    self.configure[userInput] = float(entryInput)
                                    print(f'Configured {userInput} To {str(entryInput)}')
                                else:
                                    print(f'Entry Is Not Float Value: {entryInput}')
                        else:
                            print('Object Can Not Be A Display Item Or Invalid Key Entered')

            except KeyboardInterrupt:
                self.configure['interactive.KeyboardInterruptCount'] += 1
                if int(self.configure['interactive.KeyboardInterruptCount']) >= int(self.configure['interactive.KeyboardInterruptMax']):
                    self.configure['interactive.status'] = False

    ### Build Subprocess ###
    # Build A Process For Execution
    def subprocessBuildProcess(self,commandList):
        return subprocess.Popen(commandList,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    # Communicate
    def subprocessCommunicate(self,subprocessProcess):
        stdout,stderr = subprocessProcess.communicate()
        return [stdout,stderr]
    # NMap Command Build
    def buildNmapCommand(self):
        if self.configure['root.target'] != None:
            commandList = ['nmap']
            if self.configure['nmap.sV'] == True: commandList.append('-sV')
            if self.configure['nmap.sC'] == True: commandList.append('-sC')
            if self.configure['nmap.T5'] == True: commandList.append('-T5')
            if self.configure['nmap.O']  == True and self.configure['nmap.All'] == False: commandList.append('-O')
            if self.configure['nmap.All'] == True: commandList.append('-A')
            if self.configure['nmap.verbose'] == True: commandList.append('-vv')
            if self.configure['nmap.pN'] == True: commandList.append('-Pn')
            if self.configure['nmap.sU'] == True: commandList.append('-sU')
            if self.configure['nmap.oN'] != None:
                commandList.append('-oN')
                commandList.append(str(self.configure['nmap.oN']))
            if len(self.configure['nmap.ports']) != 0:
                pInit = str(f'-p{self.configure["nmap.ports"][0]},')
                pStr  = [str(port) for port in self.configure["nmap.ports"][1:]]
                pStr  = ','.join(pStr)
                commandList.append(f'{pInit}{pStr}')
            commandList.append(self.configure['root.target'])
            return commandList
        else:
            self.exceptionHandle('buildNmapCommand()',f'Target Is Not Configured')
    # Print Command To String
    def commandListToExecStr(self,commandList):
        print(' '.join(commandList))
    ### Configuration ###
    # Set Target
    def configureTarget(self,target):
        if self.validateTarget(str(target)) == True:
            self.configure['root.target'] = str(target)
        else:
            self.exceptionHandle(f'configureTarget({target})','Target Is Invalid')
    ### Exception ###
    # Raise Exception
    def exceptionHandle(self,r,m):
        raise Exception(f'Exception:\n\tRoot Function: portScanner.{str(r)}\n\tMessage: {str(m)}')

def App():
    pScan = portScanner()
    if len(sys.argv[1:]) == 0:
        pScan.displayClearScreen()
        pScan.displayScreenKey('display.banner')
        pScan.displayInteractive()
    else:
        pScan.displayClearScreen()
        pScan.displayScreenKey('display.banner')
        argV = sys.argv[2:]
        target = str(sys.argv[1])
        pScan.configure['root.target'] = str(target)
        if len(argV) == 0:
            pScan.socketScan()
            commandList = pScan.buildNmapCommand()
            pScan.commandListToExecStr(commandList)
            if pScan.configure['interactive.runNmapPostOp'] == True:
                process = pScan.subprocessBuildProcess(commandList)
                output  = pScan.subprocessCommunicate(process)
                print(f'Nmap Output:\n{str(output[0].decode("utf-8"))}')
                sys.exit(1)
            else:
                sys.exit(1)
        else:
            for Arg in argV:
                if str(':') in str(Arg):
                    argSplit = str(Arg).split(':')
                    if str(argSplit[0]) in ['-cC','--customConfig']:
                        if argSplit[1] in ['minimal','Minimal','MINIMAL']:
                            pScan.configure['root.portMax'] = 1000
                        elif argSplit[1] in ['source','Source','SOURCE']:
                            pScan.configure['root.portMax'] = 5
                        elif argSplit[1] in ['maximum','Maximum','MAXIMUM']:
                            pScan.configure['root.portMax'] = 65535
                            pScan.configure['nmap.All']  = True
                            pScan.configure['nmap.oN']   = 'allScan.nmap'
                else:
                    ...
            pScan.displayConfigure()
            pScan.socketScan()
            commandList = pScan.buildNmapCommand()
            pScan.commandListToExecStr(commandList)
            if pScan.configure['interactive.runNmapPostOp'] == True:
                process = pScan.subprocessBuildProcess(commandList)
                output  = pScan.subprocessCommunicate(process)
                print(f'Nmap Output:\n{str(output[0].decode("utf-8"))}')
                sys.exit(1)

if __name__ == '__main__':
    App()

