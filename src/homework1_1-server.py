#!/usr/bin/env python
# _*_ coding:utf-8 _*_
__author__ = "Elijah"
__date__ = "2017/9/14 14:15"

'''
FTP开发:
     1. 用户加密认证
     2. 多用户同时登陆
     3. 每个用户有自己的家目录且只能访问自己的家目录
     4. 对用户进行磁盘配额、不同用户配额可不同
     5. 用户可以登陆server后，可切换目录
     6. 查看当前目录下文件
     7. 上传下载文件，保证文件一致性
     8. 传输过程中现实进度条
     9. 支持断点续传
'''

import hmac
import json
import os
import pickle
import random
import socketserver
import string
import struct


class ftpserver(socketserver.BaseRequestHandler):
    max_packet_size = 8192
    coding = 'utf-8'
    # BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    files_dir = '\\files\\'
    config_dir = '\\conf\\'
    download_dir = '\\download\\'

    def login(self):
        '''
        用户登陆
        :return: user_name
        '''
        user_exist = False
        flag = True
        while flag:
            print('用户进入登陆功能！即将进行用户名/密码验证......')
            with open(self.BASE_DIR + self.config_dir + 'config.txt', mode='rb') as f_r:
                config_dict = pickle.load(f_r)
            user_name = self.request.recv(1024)
            if (user_name == b'q') or (user_name == b'Q'):
                self.request.send(bytes('user_name quit', encoding=self.coding))
                print('用户在用户名阶段退出登陆功能！')
                break
            else:
                for k, v in config_dict.items():
                    if k == user_name:
                        self.request.send(bytes('user_name available', encoding=self.coding))
                        user_password = self.request.recv(1024)
                        if (user_password == b'q') or (user_password == b'Q'):
                            self.request.send(bytes('user_password quit', encoding=self.coding))
                            print('用户在密码阶段退出登陆功能！')
                            break
                        elif user_password == v[0]:
                            self.request.send(bytes('password available', encoding=self.coding))
                            client_respond = self.request.recv(1024)
                            if client_respond == b'get password available':
                                print('用户' + str(user_name, encoding=self.coding) + '密码正确！即将进行客户端验证......')
                                self.request.send(self.secret_key())
                                auth_result = self.request_auth()
                                if auth_result:
                                    self.request.send(bytes('auth_successful', encoding=self.coding))
                                    print('客户端验证成功！')
                                    flag = False
                                    user_exist = True
                                    break
                                else:
                                    self.request.send(bytes('auth_failed', encoding=self.coding))
                                    print('客户端验证失败！重新进行登录！')
                                    user_exist = True
                                    break
                            else:
                                print('客户端接收密码有效信息有误！')
                                break
                        else:
                            self.request.send(bytes('password wrong', encoding=self.coding))
                            print('用户输入密码有误！')
                            user_exist = True
                            break
                    else:
                        continue
                if not user_exist:
                    self.request.send(bytes('user_name wrong', encoding=self.coding))
                    print('用户名不存在，请重新输入！')

    def register(self):
        '''
        用户注册
        :return:
        '''
        print('用户进入注册功能！')
        flag = True
        dir_path = self.BASE_DIR + self.config_dir
        try:
            with open(os.path.join(dir_path, 'config.txt'), 'rb') as f_r:
                config_dict = pickle.load(f_r)
        except Exception as e:
            config_dict = {'': ['', '']}
        while flag:
            new_user = self.request.recv(1024)
            if (new_user == b'q') or (new_user == b'Q'):
                self.request.send(bytes('user quit', encoding=self.coding))
                print('用户退出注册功能！')
                break
            elif new_user in config_dict.keys():
                self.request.send(bytes('user exist', encoding=self.coding))
                print('用户名已经存在，无效用户名！用户重新输入！')
                continue
            elif new_user not in config_dict.keys():
                self.request.send(bytes('user available', encoding=self.coding))
                print('用户名有效！')
                new_password = self.request.recv(1024)
                if (new_password == b'q') or (new_password == b'Q'):
                    break
                else:
                    print('密码有效，接收上传目录空间配额')
                    self.request.send(bytes('password_received', encoding=self.coding))
                    user_space = self.request.recv(1024)
                    config_dict[new_user] = [new_password, user_space]
                    with open(self.BASE_DIR + self.config_dir + 'config.txt', mode='wb') as f_w:
                        pickle.dump(config_dict, f_w)
                    print('用户' + str(new_user, encoding=self.coding) + '注册成功！ 密码为：' + str(new_password,
                                                                                          encoding=self.coding) + ' 用户上传目录空间为：' + str(
                        user_space, encoding=self.coding))
                    self.request.send(bytes('Register Successful', encoding=self.coding))
                    break
            else:
                print('服务端接受注册用户名有误！')
                break

    def secret_key(self):
        '''
        √生成随机校验码，以便进行认证
        :return: 6位bytes格式的数字+字母组合校验码
        '''
        auth_key = string.ascii_lowercase + string.digits
        character = random.sample(auth_key, 6)
        string_key = "".join(character)
        bytes_key = bytes(string_key.encode(self.coding))
        return bytes_key

    def request_auth(self):
        '''
        认证客户端链接
        :return: 布尔值
        '''
        print('开始进行客户端验证......')
        msg = os.urandom(32)
        self.request.send(msg)
        key = self.request.recv(1024)
        self.request.send(bytes('received', encoding=self.coding))
        h = hmac.new(key, msg)
        digest = h.digest()
        respone = self.request.recv(len(digest))
        return hmac.compare_digest(respone, digest)

    def get_directorysize(self, file_path, size=0):
        '''
        查看filePath目录下的文件以及大小，用于判断用户配额
        :param filePath:
        :param size:
        :return:
        '''
        for root, dirs, files in os.walk(file_path):
            # print('用户的目录下包含：')
            for f in files:
                size += os.path.getsize(os.path.join(root, f))
                # print('文件：\033[4m %s \033[0m   大小：\033[1;32m %.2f \033[0m MB' % (f, ((os.path.getsize(os.path.join(root, f))) / 1048576)))
        return size

    def upload(self, head_dic):
        '''
        文件上传功能
        :param args:报头字典{'command': 操作命令, 'file_name': 文件名称, 'file_size': 文件大小,'user_name': 用户名}
        :return:
        '''
        # 读取用户磁盘限额
        with open(self.BASE_DIR + self.config_dir + 'config.txt', 'rb') as f:
            config_dict = pickle.load(f)
            space = config_dict[bytes(head_dic['user_name'],encoding=self.coding)][1]
            user_space = int(str(space,encoding=self.coding))
        while True:
            # 文件路径-每个用户一个目录
            # f_name = head_dic['file_name'].split('/')[-1]
            f_name = os.path.basename(head_dic['file_name'])
            file_path = self.BASE_DIR + self.files_dir + head_dic['user_name'] + '\\'
            try:
                os.mkdir(file_path)
            except Exception as e:
                pass
            # 文件大小
            file_size = head_dic['file_size']
            # 判断文件是否已经存在，若存在是否断点续传
            if os.path.exists(os.path.join(file_path, f_name)):
                print('用户上传文件已经存在,询问用户是否继续上传...')
                self.request.send(bytes('file_already_exist', encoding=self.coding))
                is_continue = self.request.recv(1024)
                if is_continue == b'continue_upload':
                    get_existfile_size = os.path.getsize(os.path.join(file_path, f_name))
                    temp_size = get_existfile_size
                    self.request.send(bytes(str(get_existfile_size), encoding=self.coding))
                    with open(os.path.join(file_path, f_name), 'ab') as f:
                        while temp_size < file_size:
                            recv_continue_data = self.request.recv(self.max_packet_size)
                            f.write(recv_continue_data)
                            f.flush()
                            temp_size += len(recv_continue_data)
                            print('文件继续传进度：' + str(round((temp_size / 1024), 2)) + ' KB / ' + str(
                                round((file_size / 1024), 2)) + ' KB')
                    print('客户端：' + head_dic['user_name'] + ' 文件：' + f_name + ' 上传完成！')
                    break
            else:
                # 判断用户配额空间是否充足-每个用户配额 10485760 字节
                directory_size = self.get_directorysize(file_path)
                if (directory_size + file_size) > user_space * 1024 * 1024:
                    print('用户：' + head_dic['user_name'] + ' 上传文件后目录空间将超过 ' + str(user_space) + ' MB 限额，上传文件失败！')
                    self.request.send(bytes('Insufficient_directory_space', encoding=self.coding))
                    client_received = self.request.recv(1024)
                    if client_received == b'Insufficient_directory_space_received':
                        self.request.send(space)
                        break
                else:
                    self.request.send(bytes('Directory_space_available', encoding=self.coding))
                    # 接收到的文件大小
                    recv_size = 0
                    print('----->', file_path)
                    with open(os.path.join(file_path, f_name), 'wb') as f_w:  # 必须这个打开文件，不然如果没有该文件的话报错
                        # with open(file_path, 'wb') as f_w:
                        while recv_size < file_size:
                            recv_data = self.request.recv(self.max_packet_size)
                            f_w.write(recv_data)
                            f_w.flush()
                            recv_size += len(recv_data)
                            print('文件上传进度：' + str(round((recv_size / 1024), 2)) + ' KB / ' + str(
                                round((file_size / 1024), 2)) + ' KB')
                    print('客户端：' + head_dic['user_name'] + ' 文件：' + f_name + ' 上传完成！')
                    break

    def download(self, head_dic):
        '''
        下载功能
        :param head_dic:
        :param user_name:
        :return:
        '''
        file_path = self.BASE_DIR + self.files_dir + head_dic['user_name'] + '\\'
        while True:
            send_size = 0
            files_dict = {}
            for root, dirs, files in os.walk(file_path):
                for f in files:
                    files_dict[f] = os.path.getsize(os.path.join(root, f))
            # 服务端将目录字典序列化
            files_dict_json = json.dumps(files_dict)
            # 服务端将序列化的目录字典bytes化
            files_dict_json_bytes = bytes(files_dict_json, encoding=self.coding)
            # 将bytes化的目录字典打包
            files_dict_json_bytes_struct = struct.pack('i', len(files_dict_json_bytes))
            # 服务端将打包的字典发送给客户端
            self.request.send(files_dict_json_bytes_struct)
            # 服务端接收客户端是否收到报头
            is_received = self.request.recv(1024)
            if is_received == b'files_dict_json_bytes_struct_received':
                self.request.send(files_dict_json_bytes)
                print('用户：' + head_dic['user_name'] + ' 收到上传目录文件字典！')
            else:
                print('客户端返回信息有误，请重试！')
                break
            f_name = self.request.recv(1024)
            self.request.send(bytes('file_name_received', encoding=self.coding))
            file_path = self.BASE_DIR + self.files_dir + head_dic['user_name'] + '\\'
            # with open(os.path.join(file_path, os.path.basename(f_name)), 'rb') as f:
            with open(file_path + str(f_name, encoding=self.coding), 'rb') as f:
                for line in f:
                    self.request.send(line)
                    send_size += len(line)
                    print(('文件下载进度：%.2f KB / %.2f KB') % (
                        send_size / 1024, (files_dict[str(f_name, encoding=self.coding)]) / 1024))
                is_finished = self.request.recv(1024)
                if is_finished == b'received_finished':
                    print('文件 ' + str(f_name, encoding=self.coding) + ' 下载完成！\n')
                    break
                else:
                    print('客户端接收错误，请重试！')
                    break

    def show_dir(self, head_dic):
        '''
        查看上传目录下文件
        :param head_dic:
        :param user_name:
        :return:
        '''
        file_path = self.BASE_DIR + self.files_dir + head_dic['user_name'] + '\\'
        while True:
            files_dict = {}
            for root, dirs, files in os.walk(file_path):
                for f in files:
                    files_dict[f] = os.path.getsize(os.path.join(root, f))
            # 服务端将目录字典序列化
            files_dict_json = json.dumps(files_dict)
            # 服务端将序列化的目录字典bytes化
            files_dict_json_bytes = bytes(files_dict_json, encoding=self.coding)
            # 将bytes化的目录字典打包
            files_dict_json_bytes_struct = struct.pack('i', len(files_dict_json_bytes))
            # 服务端将打包的字典发送给客户端
            self.request.send(files_dict_json_bytes_struct)
            # 服务端接收客户端是否收到报头
            is_received = self.request.recv(1024)
            if is_received == b'files_dict_json_bytes_struct_received':
                self.request.send(files_dict_json_bytes)
                print('用户：' + head_dic['user_name'] + ' 收到上传目录文件字典！')
                break
            else:
                print('客户端返回信息有误，请重试！')
                break

    def delete_file(self, head_dic):
        '''
        删除用户目录文件
        :param head_dic:
        :return:
        '''
        file_path = self.BASE_DIR + self.files_dir + head_dic['user_name'] + '\\'
        while True:
            send_size = 0
            files_dict = {}
            for root, dirs, files in os.walk(file_path):
                for f in files:
                    files_dict[f] = os.path.getsize(os.path.join(root, f))
            # 服务端将目录字典序列化
            files_dict_json = json.dumps(files_dict)
            # 服务端将序列化的目录字典bytes化
            files_dict_json_bytes = bytes(files_dict_json, encoding=self.coding)
            # 将bytes化的目录字典打包
            files_dict_json_bytes_struct = struct.pack('i', len(files_dict_json_bytes))
            # 服务端将打包的字典发送给客户端
            self.request.send(files_dict_json_bytes_struct)
            # 服务端接收客户端是否收到报头
            is_received = self.request.recv(1024)
            if is_received == b'files_dict_json_bytes_struct_received':
                self.request.send(files_dict_json_bytes)
                print('用户：' + head_dic['user_name'] + ' 收到上传目录文件字典！')
            else:
                print('客户端返回信息有误，请重试！')
                break
            f_name = self.request.recv(1024)
            self.request.send(bytes('file_name_received', encoding=self.coding))
            file_path = self.BASE_DIR + self.files_dir + head_dic['user_name'] + '\\'
            # with open(file_path+str(f_name,encoding=self.coding), 'rb') as f:
            #     for line in f:
            #         self.request.send(line)
            #         send_size += len(line)
            #         print(('文件下载进度：%.2f KB / %.2f KB')%(send_size,(files_dict[str(f_name,encoding=self.coding)])))
            is_ready_for_delete = self.request.recv(1024)
            if is_ready_for_delete == b'ready_for_delete':
                os.remove(file_path + str(f_name, encoding=self.coding))
                self.request.send(bytes('deleted_finished', encoding=self.coding))
                print(('文件：%s 删除完成！') % str(f_name, encoding=self.coding))
                break
            else:
                print('客户端接收错误，请重试！')
                break

    def handle(self):
        '''
        handle方法
        :return:
        '''
        # 循环体—用户登陆、注册
        while True:
            user_choice = self.request.recv(1024)
            if user_choice == b'1':  # 登陆
                self.login()
                print('--->这话可以删除了--->进入下一阶段功能选择！')
                break
            elif user_choice == b'2':  # 注册
                self.register()
            else:
                self.request.send(bytes('对不起，您的输入有误！请重新输入！', encoding=self.coding))
                print('用户输入有误！')
                continue
        # 循环体—开始进行通讯
        while True:
            try:
                # 接受固定报头4字节
                head_struct = self.request.recv(4)
                self.request.send(bytes('head_struct_received', encoding=self.coding))
                if not head_struct:
                    break
                # 解包报头，取出第一个报头长度
                head_len = struct.unpack('i', head_struct)[0]
                # 根据报头长度，收取序列化的字典对象
                head_json = self.request.recv(head_len).decode(self.coding)
                # 反序列化，收取字典
                head_dic = json.loads(head_json)
                # 报头字典{'command': 操作命令, 'file_name': 文件名称, 'file_size': 文件大小，'user_name': 用户名}
                # self.request.send(head_dic)
                cmd = head_dic['command']
                if hasattr(self, cmd):
                    func = getattr(self, cmd)
                    func(head_dic)
            except Exception:
                break


if __name__ == '__main__':
    server_obj = socketserver.ThreadingTCPServer(('127.0.0.1', 8080), ftpserver)
    server_obj.serve_forever()
