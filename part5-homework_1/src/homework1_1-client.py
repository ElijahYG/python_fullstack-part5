#!/usr/bin/env python
# _*_ coding:utf-8 _*_
__author__ = "Elijah"
__date__ = "2017/9/14 15:48"

import hmac
import json
import os
import socket
import struct
import pickle
from tkinter.filedialog import askopenfilename, askdirectory


class ftpclient:
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    allow_reuse_address = False
    max_packet_size = 8192
    coding = 'utf-8'
    request_queue_size = 5

    def __init__(self, server_address, connect=True):
        '''
        初始化客户端
        :param server_address: 服务器IP与Port信息
        :param connect: 是否立即创建连接，默认选项True
        '''
        self.server_address = server_address
        self.socket = socket.socket(self.address_family, self.socket_type)
        if connect:
            try:
                self.client_connect()
            except:
                self.client_close()
                raise

    def client_connect(self):
        '''
        客户端建立连接
        :return:
        '''
        self.socket.connect(self.server_address)

    def client_close(self):
        '''
        客户端关闭连接
        :return:
        '''
        self.socket.close()

    def conn_auth(self, key):
        '''
        验证客户端到服务器的链接
        :param conn:
        :return:
        '''
        msg = self.socket.recv(32)
        h = hmac.new(key, msg)
        self.socket.send(key)
        info = self.socket.recv(1024)
        if info == b'received':
            digest = h.digest()
            self.socket.sendall(digest)

    def upload(self, head_dic):
        '''
        上传文件
        :param head_dic:
        :return:
        '''
        while True:
            head_json = json.dumps(head_dic)
            head_json_bytes = bytes(head_json, encoding=self.coding)
            head_struct = struct.pack('i', len(head_json_bytes))
            self.socket.send(head_struct)
            is_received = self.socket.recv(1024)
            if is_received == b'head_struct_received':
                self.socket.send(head_json_bytes)
                send_size = 0
                is_dirspaceok_or_continue = self.socket.recv(1024)
                if is_dirspaceok_or_continue == b'file_already_exist':
                    is_continue = input('对不起，您选择的文件\033[4m ' + os.path.basename(
                        head_dic['file_name']) + ' \033[0m已经在服务端存在，是否选择断点续传(y/n)?\n>>>').strip()
                    if is_continue.lower() == 'y':
                        self.socket.send(bytes('continue_upload', encoding=self.coding))
                        existfile_size = self.socket.recv(1024)
                        with open(head_dic['file_name'], 'rb') as f:
                            f.seek(int(existfile_size))
                            for line in f:
                                self.socket.send(line)
                                send_size += len(line)
                                print('文件上传进度：' + str(round((send_size / 1024), 2)) + ' KB / ' + str(
                                    round((head_dic['file_size'] / 1024), 2)) + ' KB')
                            print('文件 ' + os.path.basename(head_dic['file_name']) + ' 上传完成！\n')
                            break
                    else:
                        print('您不选择断点续传功能，请重新选择上传文件！')
                        break
                elif is_dirspaceok_or_continue == b'Insufficient_directory_space':
                    self.socket.send(bytes('Insufficient_directory_space_received',encoding=self.coding))
                    u_space = self.socket.recv(1024)
                    print('对不起，您选择的文件\033[4m ' + os.path.basename(head_dic['file_name']) + ' \033[0m上传后将导致目录超过 \033[0;32m'+str(u_space,encoding=self.coding)+' MB \033[0m 配额空间，请选择删除文件功能移除目录下的文件以便可以再次上传，谢谢！\n')
                    break
                elif is_dirspaceok_or_continue == b'Directory_space_available':
                    with open(head_dic['file_name'], 'rb') as f:
                        for line in f:
                            self.socket.send(line)
                            send_size += len(line)
                            print('文件上传进度：' + str(round((send_size / 1024), 2)) + ' KB / ' + str(
                                round((head_dic['file_size'] / 1024), 2)) + ' KB')
                        print('文件 ' + os.path.basename(head_dic['file_name']) + ' 上传完成！\n')
                        break
                else:
                    print('对不起，服务端接收错误，请重试！')
                    break
            else:
                print('对不起，服务器端没有收到报头结构信息！')
                continue

    def download(self, head_dic):
        '''
        下载
        :return:
        '''
        while True:
            count = 0
            files_list = []
            head_json = json.dumps(head_dic)
            head_json_bytes = bytes(head_json, encoding=self.coding)
            head_struct = struct.pack('i', len(head_json_bytes))
            self.socket.send(head_struct)
            is_received = self.socket.recv(1024)
            if is_received == b'head_struct_received':
                self.socket.send(head_json_bytes)
                recv_size = 0
                files_dict_json_bytes_struct = self.socket.recv(4)
                self.socket.send(bytes('files_dict_json_bytes_struct_received', encoding=self.coding))
                if not files_dict_json_bytes_struct:
                    break
                files_dict_json_len = struct.unpack('i', files_dict_json_bytes_struct)[0]
                files_dict_json = self.socket.recv(files_dict_json_len).decode(self.coding)
                files_dict = json.loads(files_dict_json)
                print('用户：' + head_dic['user_name'] + '的目录为：')
                for k, v in files_dict.items():
                    count += 1
                    files_list.append(k)
                    print(('%s 、文件：\033[4m %s \033[0m   大小：\033[1;32m %.2f \033[0m MB') % (count, k, (v / 1048576)))
                user_download_choice = input('请输入要下载文件的编号：\n>>>').strip()
                for i, val in enumerate(files_list):
                    if int(user_download_choice) == (i + 1):
                        download_filename = val
                        self.socket.send(bytes(download_filename, encoding=self.coding))
                        break
                    else:
                        download_filename = ''
                is_filename_received = self.socket.recv(1024)
                if (download_filename != '') and (is_filename_received == b'file_name_received'):
                    with open(os.path.join(head_dic['file_name'], os.path.basename(download_filename)),
                              'wb') as f_w:  
                        while recv_size < int(files_dict[download_filename]):
                            recv_data = self.socket.recv(self.max_packet_size)
                            f_w.write(recv_data)
                            recv_size += len(recv_data)
                            print(('文件下载进度：%.2f KB / %.2f KB') % (
                                recv_size / 1024, (files_dict[download_filename]) / 1024))
                    self.socket.send(bytes('received_finished', encoding=self.coding))
                    print('用户：' + head_dic['user_name'] + ' 文件：' + download_filename + ' 下载完成！\n')
                    break
                else:
                    print('选择的文件不存在！')
                    continue
            else:
                print('对不起，服务器端没有收到报头结构信息！')
                continue

    def show_dir(self, head_dic):
        '''
        查看用户上传目录
        :return:
        '''
        while True:
            head_json = json.dumps(head_dic)
            head_json_bytes = bytes(head_json, encoding=self.coding)
            head_struct = struct.pack('i', len(head_json_bytes))
            self.socket.send(head_struct)
            is_received = self.socket.recv(1024)
            if is_received == b'head_struct_received':
                self.socket.send(head_json_bytes)
                files_dict_json_bytes_struct = self.socket.recv(4)
                self.socket.send(bytes('files_dict_json_bytes_struct_received', encoding=self.coding))
                if not files_dict_json_bytes_struct:
                    break
                files_dict_json_len = struct.unpack('i', files_dict_json_bytes_struct)[0]
                files_dict_json = self.socket.recv(files_dict_json_len).decode(self.coding)
                files_dict = json.loads(files_dict_json)
                print('用户：' + head_dic['user_name'] + '的上传目录为：')
                for k, v in files_dict.items():
                    print(('文件：\033[4m %s \033[0m   大小：\033[1;32m %.2f \033[0m MB') % (k, (v / 1048576)))
                break
            else:
                print('对不起，服务器端没有收到报头结构信息！')
                continue

    def delete_file(self, head_dic):
        '''
        删除用户目录下文件
        :param head_dic:
        :return:
        '''
        while True:
            count = 0
            files_list = []
            head_json = json.dumps(head_dic)
            head_json_bytes = bytes(head_json, encoding=self.coding)
            head_struct = struct.pack('i', len(head_json_bytes))
            self.socket.send(head_struct)
            is_received = self.socket.recv(1024)
            if is_received == b'head_struct_received':
                self.socket.send(head_json_bytes)
                recv_size = 0
                files_dict_json_bytes_struct = self.socket.recv(4)
                self.socket.send(bytes('files_dict_json_bytes_struct_received', encoding=self.coding))
                if not files_dict_json_bytes_struct:
                    break
                files_dict_json_len = struct.unpack('i', files_dict_json_bytes_struct)[0]
                files_dict_json = self.socket.recv(files_dict_json_len).decode(self.coding)
                files_dict = json.loads(files_dict_json)
                print('用户：' + head_dic['user_name'] + '的目录为：')
                for k, v in files_dict.items():
                    count += 1
                    files_list.append(k)
                    print(('%s 、文件：\033[4m %s \033[0m   大小：\033[1;32m %.2f \033[0m MB') % (count, k, (v / 1048576)))
                user_delete_choice = input('请输入要\033[1;31m删除\033[0m文件的编号：\n>>>').strip()
                for i, val in enumerate(files_list):
                    if int(user_delete_choice) == (i + 1):
                        delete_filename = val
                        self.socket.send(bytes(delete_filename, encoding=self.coding))
                        break
                    else:
                        delete_filename = ''
                is_filename_received = self.socket.recv(1024)
                if (delete_filename != '') and (is_filename_received == b'file_name_received'):
                    self.socket.send(bytes('ready_for_delete', encoding=self.coding))
                    is_finished = self.socket.recv(1024)
                    if is_finished == b'deleted_finished':
                        print('用户：' + head_dic['user_name'] + ' 文件：\033[4m ' + delete_filename + ' \033[0m删除完成！\n')
                        break
                    else:
                        print('对不起，删除文件出错，请重试！')
                        break
                else:
                    print('选择的文件不存在或删除失败，请重试！')
                    continue
            else:
                print('对不起，服务器端没有收到报头结构信息！')
                continue

    def user_exit(self, head_dic):
        print('用户：' + head_dic['user_name'] + '退出！')
        exit()

    def operation(self):
        '''
        用户执行功能
        :return:
        '''
        u_space = 0
        end_loop = True
        while end_loop:
            input_choice = input('您好，请输入您要选择功能的对应编号：\n1、登陆\n2、注册\n3、退出\n>>>').strip()
            if input_choice == '1':  # 登陆
                self.socket.send(input_choice.encode(self.coding))
                while True:
                    user_name = input('你好，请输入用户名(或者输入q退出)：\n>>>').strip()
                    self.socket.send(user_name.encode(self.coding))
                    data_username = self.socket.recv(1024)
                    if data_username == b'user_name quit':
                        print('用户退出登陆程序！')
                        break
                    elif data_username == b'user_name available':
                        user_password = input('欢迎你！' + user_name + '请输入密码(或者输入q退出)：\n>>>').strip()
                        self.socket.send(user_password.encode(self.coding))
                        data_password = self.socket.recv(1024)
                        if data_password == b'user_password quit':
                            print('用户退出登陆程序！')
                            break
                        elif data_password == b'password available':
                            self.socket.send(bytes('get password available', encoding=self.coding))
                            print('密码正确！进行客户端验证！')
                            data_key = self.socket.recv(1024)
                            print('接收到从服务端发来的验证码 ' + str(data_key, encoding=self.coding) + ' 正在进行验证....')
                            self.conn_auth(data_key)
                            data_authresult = self.socket.recv(1024)
                            if data_authresult == b'auth_successful':
                                print('客户端验证成功！进入下一阶段功能选择！')
                                end_loop = False
                                break
                            elif data_authresult == b'auth_failed':
                                print('验证失败，请重新进行登录操作！谢谢！')
                                continue
                        elif data_password == b'password wrong':
                            print('对不起，您输入的密码有误，请重新输入！')
                            continue
                        else:
                            print('对不起，您的输入有误，请重新输入！')
                            continue
                    elif data_username == b'user_name wrong':
                        print('对不起，您输入的用户名有误！')
                        continue
            elif input_choice == '2':  # 注册
                self.socket.send(input_choice.encode(self.coding))
                while True:
                    new_user = input('你好，请输入要注册的用户名(或者输入q退出)：\n>>>').strip()
                    self.socket.send(new_user.encode(self.coding))
                    data = self.socket.recv(1024)
                    if data == b'user exist':
                        print('对不起，您输入的用户名已经被注册，请重新输入！')
                        continue
                    elif data == b'user available':
                        new_password = input('用户名有效，请输入密码！(或者输入q退出)\n>>>').strip()
                        self.socket.send(new_password.encode(self.coding))
                        is_received = self.socket.recv(1024)
                        if is_received == b'password_received':
                            user_space = input('请输入用户上传目录的空间配额！(或者输入q退出)：\n(默认10MB)>>>').strip()
                            self.socket.send(bytes(user_space, encoding=self.coding))
                            data = self.socket.recv(1024)
                            if data == b'Register Successful':
                                print('用户' + new_user + '注册成功！ 密码为：' + new_password + ' 用户上传目录空间为：' + user_space + 'MB')
                                u_space = user_space
                                break
                            else:
                                print('对不起，注册失败，请重新注册！')
                                continue
                        else:
                            print('对不起，服务端接收密码有误，请重新注册！')
                            continue
                    elif data == b'user quit':
                        print('用户退出注册功能！')
                        break
            elif input_choice == '3':
                print('欢迎下次使用！')
                exit()
            else:
                print('对不起，您输入的功能编号有误，请重新输入！')
                continue

        end_func = True
        choice_dict = {'1': 'upload', '2': 'download', '3': 'show_dir', '4': 'delete_file', '5': 'user_exit', }
        while end_func:
            func_choice = input('用户:' + user_name + ' 请选择功能：\n1、上传文件\n2、下载文件\n3、查看目录\n4、删除文件\n5、退出\n>>>:').strip()
            user_command = choice_dict[func_choice]
            if (func_choice == '1'):
                file_name = askopenfilename(filetypes=(("All files", "*.*"),))
                file_size = os.path.getsize(file_name)
                head_dic = {'command': user_command, 'file_name': file_name, 'file_size': file_size,
                            'user_name': user_name}
            elif func_choice == '2':
                file_name = askdirectory(title='选择下载至目录')
                file_size = ''
                head_dic = {'command': user_command, 'file_name': file_name, 'file_size': file_size,
                            'user_name': user_name}
            else:
                file_name = ''
                file_size = ''
                head_dic = {'command': user_command, 'file_name': file_name, 'file_size': file_size,
                            'user_name': user_name}
            if hasattr(self, user_command):
                func = getattr(self, user_command)
                func(head_dic)


if __name__ == '__main__':
    client = ftpclient(('127.0.0.1', 8080))
    client.operation()
