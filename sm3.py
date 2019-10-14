from gmssl import sm3
import sm3Attack
import sys

# 长度扩展攻击的过程：
# 已知hash(secret)=55e12e91650d2fec56ec74e1d3e4ddbfce2ef3a65890c2a19ecf88a307e76a23，len(secret)=4，未知secret
# sm3为大端方式，修改第二轮IV为hash(secret),可用于求hash(secret||padding||length||x)
# 构造任意str使得len(str)==len(secret)，第一轮计算后截断，结果IV修改为hash(secret)的分组，再进行第二轮，即可求得可用于求hash(secret||padding||length||x)

#字符串转ASCII码
def strToASCII(string):
    li = []
    for s in string:
        li.append(ord(s))
    return li

if __name__ == '__main__':
    #hash('test')==55e12e91650d2fec56ec74e1d3e4ddbfce2ef3a65890c2a19ecf88a307e76a23
    # strA='test'
    # strSecond = 'atta'


    strA=input('please input string to sm3:')#输入secret的值，后面计算中secret当做未知，仅知道其长度和hash值
    strSecond=input('please input second part message:')#输入第二轮计算的字符串

    length=len(strA)#计算secret的长度
    y=sm3.sm3_hash(strToASCII(strA))#计算secret的hash值用于修改二轮IV，存在y中
    # print(y)

    #对hash(secret)进行分组，用于求二轮的IV，分组存在liNum中
    liStr=[]
    liNum=[]
    count = 0
    for i in range(0,len(y)+1):
        if (count % 8 == 0 and count!=0):
            liStr.append('0x'+y[i-8:i])
        count=count+1
    for x in liStr:
        liNum.append(int(x,16))
    # print(count)
    # print(liStr)
    # print(liNum)

    #strARadom='aaaa'
    # strPadding='\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # strLength1 = '\x00\x00\x00\x00\x00\x00'

    strARadom='a'*length#填充第一轮中的secret部分，长度相等即可
    strPadding='\x80'+'\x00'*(56-length-1)#填充第一轮剩余部分
    strLength1 = '\x00'*6#第一轮数据长度前半部分
    #根据第一轮secret长度分类填写长度部分
    if length*8<256:
        strLength=strLength1+'\x00'+bytes([length*8]).decode('utf-8')
    else:
        strLength1=strLength1+bytes([(length-32)*8]).decode('utf-8')+'\xff'

    # 输出hash(secret||padding||length||x)用于对比验证攻击是否成功
    y2 = sm3.sm3_hash(strToASCII(strA + strPadding + strLength + strSecond))
    print('hash(secret||padding||length||x)为：')
    print(y2)


    # 将新的IV，即liNum传入sm3Attack进行攻击
    y1 = sm3Attack.sm3_hash(strToASCII(strARadom+strPadding+strLength+strSecond),liNum)
    print('使得length(random)==length(secret),并利用hash(secret)修改IV进行攻击后hash(random||padding||length||x)为：')
    print(y1)#若secret=test,x=atta,值为613e409031cf41aa47f49808731198598b097c5a4fea0cf2997355b9a966a949

