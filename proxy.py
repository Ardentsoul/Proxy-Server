import socket
import sys
import time
from socket import *
from _thread import *

ATTACK_RESPONSE_MESSAGE_BODY = b'HTTP/1.1 200 OK\r\n\r\n<!DOCTYPE html>\r\n<html>\r\n' \
                               b'<body>You are being attacked</body>\r\n</html>'
BAD_REQUEST = b'HTTP/1.1 400 - Bad Request'
IMAGE_URL = b'http://ocna0.d2.comp.nus.edu.sg:50000/change.jpg'
BUFFER_SIZE = 8192
TIME_OUT_TIMER = 10
REFRESH_RATE = 1

hashMap = {}
headerMethodArray = [b"GET"]
HTTPArray = [b"HTTP/1.0", b"HTTP/1.1"]
validImageExtArray = [b'jpg', b'jpeg', b'png', b'ico', b'bmp', b'cur', b'tif', b'tiff', b'svg', b'webp', b'jfif',
                      b'pjpeg', b'pjp', b'apng', b'avif', b'gif']

proxyPort = int(sys.argv[1])  # port the proxy listens on
isSubstitute = int(
    sys.argv[2])  # binary value specifying whether proxy applies image substitution (0 == false, 1 == true)
isAttack = int(sys.argv[3])  # binary value specifying whether proxy implements attack mode (0 == false, 1 == true)


def start():
    try:
        proxyServerSocket = socket(AF_INET, SOCK_STREAM)  # create TCP welcome socket
        proxyServerSocket.bind(('', proxyPort))
        proxyServerSocket.listen()
        #print("Server started successfully [ %d ]" % proxyPort)

    except Exception:
        #print("[*] Unable to initialize socket")
        #print(Exception)
        sys.exit(2)

    while True:
        try:
            connectionSocket, addr = proxyServerSocket.accept()
            data = connectionSocket.recv(BUFFER_SIZE)
            isValid = validityCheck(connectionSocket, data)
            if isValid:
                if isAttack == 1:
                    connectionSocket.send(ATTACK_RESPONSE_MESSAGE_BODY)
                    connectionSocket.close()
                    continue
                elif isSubstitute == 1:
                    data = substituteImage(data)
                start_new_thread(fetchData, (connectionSocket, data, addr))  # start a new thread
                # print(data)
        except KeyboardInterrupt:
            connectionSocket.close()
            #print("\n[*] Shutdown")
            sys.exit(1)


def validityCheck(sourceSocket, data):
    try:
        # parse the first line
        firstLine = data.split(b'\n')[0]

        # parse the second line
        secondLine = data.split(b'\n')[1]

        # get header method
        header = firstLine.split()[0]

        # get http version
        httpVersion = firstLine.split()[2]

        # check header method is valid
        if header not in headerMethodArray:
            sourceSocket.send(BAD_REQUEST)
            sourceSocket.close()
            return False

        # check HTTP version is valid
        if httpVersion not in HTTPArray:
            sourceSocket.send(BAD_REQUEST)
            sourceSocket.close()
            return False

        # check Host Header is valid
        try:
            # get host header
            hostHeader = secondLine.split()[0]
            if httpVersion == HTTPArray[1] and hostHeader != b'Host:':
                sourceSocket.send(BAD_REQUEST)
                sourceSocket.close()
                return False
        except Exception:
            return False

        return True
    except Exception:
        return False


def substituteImage(data):
    # get first line
    firstLine = data.split(b'\n')[0]

    # get url
    url = firstLine.split()[1]

    # Method 1: check for image based on header
    if data.find(b'Accept: image') != -1:
        data = data.replace(url, IMAGE_URL)
    return data

    # Method 2 : check based on hardcoded extensions
    # split url by '/'
    # urlSections = url.split(b'/')
    #
    # # get the last element of urlSection
    # lastSection = urlSections[-1]
    #
    # # extract the img extension type
    # extension = lastSection.split(b'.')[-1]
    #
    # if extension in validImageExtArray:
    #     data = data.replace(url, IMAGE_URL)
    #     return data
    # else:
    #     return data


def fetchData(sourceSocket, data, clientAddr):
    try:
        # remove persistent connection
        data = data.replace(b'Connection: keep-alive', b'Connection: close')

        refererUrl = None

        # Check whether there exists a referer field to check request comes from the same webpage
        if data.find(b'Referer: ') != -1:
            splitData = data.split(b'Referer: ')[1]
            refererUrl = splitData.split(b'\r\n')[0]

        # parse the first line
        firstLine = data.split(b'\n')[0]

        # get url
        url = firstLine.split(b' ')[1]

        # find pos of ://
        httpPos = url.find(b'://')

        if httpPos != -1:
            # get the rest of url
            temp = url[(httpPos + 3):]

        else:
            temp = url

        # find end of web server
        webserverPos = temp.find(b'/')
        # find the port pos (if any)
        portPos = temp.find(b':')

        if webserverPos == -1:
            webserverPos = len(temp)

        webserver = ""
        port = -1
        if webserverPos < portPos or portPos == -1:
            # default port
            port = 80
            webserver = temp[:webserverPos]

        # specific port
        else:
            port = int((temp[(portPos + 1):])[:webserverPos - portPos - 1])
            webserver = temp[:portPos]

        connectToDestServer(webserver, sourceSocket, data, port, url, clientAddr, refererUrl)

    except Exception:
        pass


def connectToDestServer(webserver, sourceSocket, data, port, url, clientAddr, refererUrl):
    try:
        flag = False
        IPAddr = clientAddr[0]

        if refererUrl is not None:  # use referer url as base url
            if (refererUrl, IPAddr) not in hashMap:
                flag = True
                hashMap[(refererUrl, IPAddr)] = (0, TIME_OUT_TIMER)
            baseUrl = refererUrl
        else:  # use url as base url
            flag = True
            hashMap[(url, IPAddr)] = (0, TIME_OUT_TIMER)
            baseUrl = url

        webserverSocket = socket(AF_INET, SOCK_STREAM)
        webserverSocket.connect((webserver, port))
        webserverSocket.send(data)

        contentLength = b''
        messageBodySize = 0
        while True:
            # receive data from web server
            reply = webserverSocket.recv(BUFFER_SIZE)
            if len(reply) > 0:
                contentLength += reply
                sourceSocket.send(reply)  # send to browser/client
            else:
                sourceSocket.shutdown(SHUT_RDWR)
                break

            # restart timer for every object sent
            sizeOfPayload = hashMap[(baseUrl, IPAddr)][0] # get 1st value of key
            hashMap[(baseUrl, IPAddr)] = (sizeOfPayload, TIME_OUT_TIMER)

        webserverSocket.close()
        sourceSocket.close()

        # Telemetry calculation
        replySegment = contentLength.split(b'\r\n\r\n')
        bodySegment = replySegment[1]
        # > 1 means there exists a header and body with indexes 0 and 1 respectively
        if len(replySegment) > 1:
            messageBodySize = len(bodySegment)

        # Update key pair value pair (payloadSize, timer)
        timeLeft = hashMap[(baseUrl, IPAddr)][1]
        payloadSize = messageBodySize + hashMap[(baseUrl, IPAddr)][0]
        hashMap[(baseUrl, IPAddr)] = (payloadSize, timeLeft)

        if flag:
            while hashMap[(baseUrl, IPAddr)][1] > 0:
                # decrement timer value
                payloadSize = hashMap[(baseUrl, IPAddr)][0]
                timeLeft = hashMap[(baseUrl, IPAddr)][1] - REFRESH_RATE
                hashMap[(baseUrl, IPAddr)] = (payloadSize, timeLeft)
                time.sleep(REFRESH_RATE)
            # extract total payload size
            payloadSize = hashMap[(baseUrl, IPAddr)][0]
            print(url.decode("utf-8") + ", " + str(payloadSize))
            del hashMap[(baseUrl, IPAddr)]

    except socket.error:
        webserverSocket.close()
        sourceSocket.close()
        #print(webserverSocket.error)
        sys.exit(1)


start()
