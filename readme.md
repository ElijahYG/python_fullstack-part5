# python_fullstack
## [我的博客](http://blog.csdn.net/dragonyangang "我的博客")

# 第五模块：作业1：FTP开发
    Readme
    Author: Elijah
    Time: 2017-09-14
    Function:FTP开发——要求
        1. 用户加密认证
        2. 多用户同时登陆
        3. 每个用户有自己的家目录且只能访问自己的家目录
        4. 对用户进行磁盘配额、不同用户配额可不同
        5. 用户可以登陆server后，可切换目录
        6. 查看当前目录下文件
        7. 上传下载文件，保证文件一致性
        8. 传输过程中现实进度条
        9. 支持断点续传
    Need Environment：Python 3.5 、PyCharm
    Move：
    Feature：
    Important py file：hmac、json、os、pickle、random、socketserver、string、struct
    How To：操作流程如下：
    1、用户执行homework1_1-server.py、homework1_1-client.py文件开启服务端和客户端
    2、首次使用先进行用户注册，用户输入用户和密码进行注册，注册成功后系统返回
    3、已经注册成功的用户选择登陆功能，输入用户名和密码，正确后服务端还会发送4位字母和数字的组合随机码进行验证，客户端收到之后解析返回服务端进行有效性验证，验证成功则登陆成功
    4、登陆成功后进入功能选择界面，功能包括：上传文件、下载文件、查看目录、删除文件和退出
    5、上传文件功能：用户选择文件上传至服务端用户目录，可以多次上传文件，用户上传文件目录大小有限额限制，也可以断点续传，上传过程中显示上传进度
    6、下载文件功能：用户选择服务端用户目录的文件进行下载，可以多次进行下载，下载过程中显示下载进度
    7、查看目录功能：用户可以查看服务端用户目录下的所有文件，以便进行下载和删除管理
    8、删除文件功能：用户可以删除服务端用户目录下的文件，以便释放目录空间
    9、退出功能：用户退出
    个人发挥：用模块化的编程思想
- 个人博客地址：http://blog.csdn.net/dragonyangang/article/details/78181799

# 第五模块：作业2：批量主机管理工具开发
    Readme
    Author: Elijah
    Time: 2017-10-08
    Function:批量主机管理工具开发-要求
        1.实现批量命令执行、文件分发
    Need Environment：Python 3.5 、PyCharm
    Move：
    Feature：
    Important py file：paramiko、multiprocessing
    How To：
    操作流程如下：
    1、先将所有主机ip、用户名、密码、端口号信息配置在settings.py文件中
    2、用户执行main.py接口执行文件，系统读取settings.py文件内容，输出主机组字典
    3、用户选择想要批量操作的主机组编号，系统返回该组内主机ip
    4、用户可以执行相应命令进行批量操作，系统会将结果返回输出
    5、用户也可以批量上传文件至所有主机，成功后返回上传功能提示
    6、采用多进程进行
    个人发挥：用模块化的编程思想
- 个人博客地址：http://blog.csdn.net/dragonyangang/article/details/78181896

[回到顶部](#readme)
