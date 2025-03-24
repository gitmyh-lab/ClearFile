# coding:utf-8
# file: ClearFile.py
import tkinter
import tkinter.messagebox, tkinter.simpledialog, tkinter.filedialog
import os, os.path
import threading
import time
import zipfile
import hashlib
from datetime import datetime, timedelta
import ctypes
import psutil
ctypes.windll.kernel32.SetDllDirectoryW(None)  # 解除路径长度限制

import logging
logging.basicConfig(filename='cleaner.log', level=logging.DEBUG)
rubbishExt = ['.tmp', '.bak', '.old', '.wbk', '.xlk', '._mp', '.log', '.gid', '.chk', '.syd', '.$$$', '.@@@', '.~*']

def GetDrives():
    """获取所有有效磁盘盘符"""
    drives = []
    for i in range(65, 91):  # ASCII码A-Z
        drive_letter = chr(i)
        # 使用Windows标准路径格式（C:\）
        vol = f"{drive_letter}:\\"
        # 增加有效性检查（排除不可访问的驱动器）
        try:
            if os.path.isdir(vol):
                drives.append(vol)
        except PermissionError:
            continue  # 跳过无权限访问的驱动器（如某些光驱）
    return drives

class AdvancedScanner:
    """增强版垃圾文件扫描器（完整多级过滤逻辑）"""
    def __init__(self):
        # 初始化保护路径列表（论文4.2.1节路径预筛选）
        self.protected_paths = [
            os.path.normpath(r'C:\Windows'),  # Windows系统目录，规范化路径
            os.path.normpath(r'C:\Program Files'),  # 应用程序目录
            os.path.expanduser('~\\Documents')  # 用户文档目录，展开~
        ]

        # 文件属性过滤条件（论文4.2.1节文件属性验证）
        self.max_age_days = 30  # 30天未修改
        self.max_age_seconds = self.max_age_days * 86400 #转化为秒数
        self.min_size = 1 * 1024 * 1024  # 1MB以下文件

        # 垃圾文件扩展名列表（从rubbishExt来的）
        self.rubbish_ext = [ext.lower() for ext in rubbishExt]  # 使用全局变量

    def is_protected_path(self, current_path):
        """
        路径预筛选（保护系统关键目录）
        :param current_path: 当前遍历的目录路径
        :return: True表示需要跳过此目录，False表示可以扫描
        """
        normalized_path = os.path.normpath(current_path).lower()
        for p in self.protected_paths:
            if normalized_path.startswith(os.path.normpath(p).lower()):
                return True
        return False

    def validate_file_attributes(self, file_path):
        """
        文件属性验证（论文4.2.1节三级过滤）
        :param file_path: 待验证文件完整路径
        :return: 符合垃圾文件条件返回True
        """
        try:
            stat = os.stat(file_path)# 获取文件状态信息
            is_old = (time.time() - stat.st_mtime) > self.max_age_seconds # 条件1：文件最后修改时间超过30天
            is_small = stat.st_size < self.min_size # 条件2：文件尺寸小于1MB
            ext = os.path.splitext(file_path)[1].lower() # 条件3：扩展名在黑名单中
            return ext in self.rubbish_ext and (is_old or is_small)
        except (PermissionError, FileNotFoundError):
            return False

class BackupManager:
    """备份与恢复模块（论文4.2.3节）"""

    def __init__(self):
        # 初始化备份存储路径
        self.backup_dir = os.path.join(os.path.expanduser("~"), "CleanerBackups")
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            # 检查目录是否可写
            if not os.access(self.backup_dir, os.W_OK):
                raise PermissionError(f"无权限写入备份目录: {self.backup_dir}")
        except Exception as e:
            tkinter.messagebox.showerror("备份错误", str(e))

        # 配置参数（可从配置文件加载）
        self.retention_days = 30  # 备份保留天数

    def create_backup(self, file_list, backup_tag="auto"):
        """
        创建备份（论文4.2.3节全量压缩）
        :param file_list: 需要备份的文件路径列表
        :param backup_tag: 备份标识（用于手动备份分类）
        :return: 备份文件路径
        """
        if not file_list:
            return None
        logging.info(f"开始备份 {len(file_list)} 个文件")
        # 生成带时间戳的备份文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{backup_tag}_{timestamp}.zip"
        backup_path = os.path.join(self.backup_dir, backup_name)

        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in file_list:
                    logging.debug(f"正在备份: {file_path}")
                    try:
                        if self._is_file_locked(file_path):
                            print(f"文件被占用，跳过备份: {file_path}")
                            continue
                        if not os.path.exists(file_path):
                            logging.warning(f"文件不存在，跳过备份: {file_path}")
                            continue
                        # 检查文件可读性
                        if not os.access(file_path, os.R_OK):
                            logging.error(f"无读取权限，跳过备份: {file_path}")
                            continue
                        if os.path.exists(file_path):
                            arcname = os.path.relpath(file_path, start=os.path.dirname(file_path))
                            zipf.write(file_path, arcname)
                            # 记录元数据（论文4.2.3节）
                            info = zipfile.ZipInfo.from_file(file_path)
                            zipf.writestr(f"meta/{arcname}.info",
                                          f"Original Path: {file_path}\n"
                                          f"Size: {os.path.getsize(file_path)} bytes\n"
                                          f"Hash: {self._calculate_md5(file_path)}")
                    except Exception as e:
                        logging.error(f"文件 {file_path} 备份失败: {str(e)}", exc_info=True)
            return backup_path
        except PermissionError:
            logging.error(f"备份操作全局错误: {str(e)}", exc_info=True)
            return None
    def _is_file_locked(self, file_path):
        """检查文件是否被其他进程占用"""
        for proc in psutil.process_iter():
            try:
                files = proc.open_files()
                if any(f.path == file_path for f in files):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def restore_backup(self, zip_path, target_dir=None):
        """
        恢复备份（论文4.2.3节冲突处理）
        :param zip_path: 备份ZIP文件路径
        :param target_dir: 自定义恢复目录（None则恢复到原始路径）
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # 优先读取元数据
                meta_files = [f for f in zipf.namelist() if f.startswith('meta/')]
                restore_map = {}  # {压缩包内路径: 原始路径}

                # 解析元数据
                for meta in meta_files:
                    content = zipf.read(meta).decode()
                    original_path = content.split("Original Path: ")[1].split("\n")[0]
                    restore_map[meta.replace('meta/', '', 1).replace('.info', '')] = original_path

                # 解压文件
                for file in zipf.namelist():
                    if not file.startswith('meta/'):
                        original_path = restore_map.get(file, None)
                        if target_dir:  # 自定义恢复路径
                            target_path = os.path.join(target_dir, os.path.basename(file))
                        else:
                            target_path = original_path if original_path else os.path.join(self.backup_dir, file)

                        # 处理路径冲突（论文4.2.3节）
                        if os.path.exists(target_path):
                            base, ext = os.path.splitext(target_path)
                            target_path = f"{base}_restored{ext}"

                        # 写入文件并验证哈希
                        zipf.extract(file, target_dir or os.path.dirname(target_path))
                        if original_path and (target_dir is None):
                            os.rename(os.path.join(target_dir or "", file), target_path)
                            # 哈希校验可在此添加
            return True
        except Exception as e:
            print(f"恢复失败: {str(e)}")
            return False

    def cleanup_old_backups(self):
        """清理过期备份（论文4.2.3节存储优化）"""
        now = datetime.now()
        for fname in os.listdir(self.backup_dir):
            if fname.endswith(".zip"):
                try:
                    # 从文件名解析时间戳
                    date_str = fname.split("_")[2].split(".")[0]
                    file_date = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
                    if (now - file_date) > timedelta(days=self.retention_days):
                        os.remove(os.path.join(self.backup_dir, fname))
                except:
                    continue

    def _calculate_md5(self, file_path):
        """计算文件MD5（用于校验）"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

class Window:
    def __init__(self):
        self.root = tkinter.Tk()
        # 创建菜单
        menu = tkinter.Menu(self.root)
        # 创建“系统”子菜单
        submenu = tkinter.Menu(menu, tearoff=0)
        submenu.add_command(label="关于...", command=self.MenuAbout)
        submenu.add_separator()
        submenu.add_command(label="退出", command=self.MenuExit)
        menu.add_cascade(label="系统", menu=submenu)
        # 创建“清理”子菜单
        submenu = tkinter.Menu(menu, tearoff=0)
        submenu.add_command(label="扫描垃圾文件", command=self.MenuScanRubbish)
        submenu.add_command(label="删除垃圾文件", command=self.MenuDelRubbish)
        submenu.add_command(label="恢复备份", command=self.MenuRestoreBackup)
        menu.add_cascade(label="清理", menu=submenu)
        # 创建“查找”子菜单
        submenu = tkinter.Menu(menu, tearoff=0)
        submenu.add_command(label="搜索大文件", command=self.MenuScanBigFile)
        submenu.add_separator()
        submenu.add_command(label="按名称搜索文件", command=self.MenuSearchFile)
        menu.add_cascade(label="搜索", menu=submenu)
        self.root.config(menu=menu)
        # 创建标签，用于显示状态信息
        self.progress = tkinter.Label(self.root, anchor=tkinter.W,
                                      text='状态', bitmap='hourglass', compound='left')
        self.progress.place(x=10, y=370, width=480, height=15)
        # 创建文本框，显示文件列表
        self.flist = tkinter.Text(self.root)
        self.flist.place(x=10, y=10, width=480, height=350)
        # 为文本框添加垂直滚动条
        self.vscroll = tkinter.Scrollbar(self.flist)
        self.vscroll.pack(side='right', fill='y')
        self.flist['yscrollcommand'] = self.vscroll.set
        self.vscroll['command'] = self.flist.yview
        self.scanned_files = []  #存储扫描到的完整路径

    def MainLoop(self):
        self.root.title("ClearFile")
        self.root.minsize(500, 400)
        self.root.maxsize(500, 400)
        self.root.mainloop()

    # “关于”菜单
    def MenuAbout(self):
        tkinter.messagebox.showinfo("ClearFile",
                                    "这是使用 Python 编写的 Windows 优化程序。\n 欢迎使用并提出宝贵意见！")

    # "退出"菜单
    def MenuExit(self):
        self.root.quit()

    # "扫描垃圾文件"菜单
    def MenuScanRubbish(self):
        """扫描菜单事件处理（集成新扫描器）"""
        result = tkinter.messagebox.askquestion("ClearFile", "扫描垃圾文件将需要较长的时间，是否继续?")
        if result == 'no':
            return
        try:
            self.scanner = AdvancedScanner()  # 使用新扫描器
            self.drives = GetDrives()
            t = threading.Thread(target=self._threaded_scan)
            t.start()
        except Exception as e:
            tkinter.messagebox.showerror("错误", f"扫描初始化失败: {str(e)}")

    def _threaded_scan(self):
        """后台扫描线程（论文4.3.1节多线程资源管理）"""
        try:
            self.flist.delete(0.0, tkinter.END)
            self.scanned_files.clear()  # 清空历史数据
            total_size = 0
            file_count = 0

            for drive in self.drives:
                # 使用生成器逐文件处理
                for file_path in self._scan_drive(drive):
                    self.scanned_files.append(file_path)  # 存储完整路径
                    try:
                        file_size = os.path.getsize(file_path)
                        total_size += file_size
                    except OSError:
                        continue

                    display_path = self._truncate_path(file_path)
                    self.flist.insert(tkinter.END, f"{display_path}\n")
                    file_count += 1
                    self.progress['text'] = f"已找到 {file_count} 个文件"

            self.progress['text'] = f"找到 {file_count} 个垃圾文件，共占用 {total_size / 1024 / 1024:.2f} MB"
        except Exception as e:
            tkinter.messagebox.showerror("扫描错误", str(e))

    def _scan_drive(self, drive_path):
        """驱动扫描封装方法"""
        scanner = self.scanner
        for root, dirs, files in os.walk(drive_path, topdown=True):
            if scanner.is_protected_path(root):
                dirs[:] = []  # 关键！跳过子目录
                continue
            for filename in files:
                file_path = os.path.join(root, filename)
                if scanner.validate_file_attributes(file_path):
                    yield file_path

    def _truncate_path(self, path, max_len=50):
        """路径截断显示优化"""
        if len(path) <= max_len:
            return path
        return f"{path[:20]}...{path[-27:]}"

    # "删除垃圾文件"菜单
    def MenuDelRubbish(self):
        """删除菜单事件处理（论文4.2.2节安全机制）"""
        result = tkinter.messagebox.askquestion("ClearFile", "删除垃圾文件将需要较长的时间，是否继续?")
        if result == 'no':
            return

        # 获取待删除文件列表
        delete_files = self.scanned_files

        # 启动备份线程
        t_backup = threading.Thread(target=self._threaded_backup_and_delete, args=(delete_files,))
        t_backup.start()
        tkinter.messagebox.showinfo('清理已完成！')

    def _threaded_backup_and_delete(self, delete_files):
        """后台执行备份+删除"""
        try:
            # 创建备份
            backup = BackupManager()
            backup_path = backup.create_backup(delete_files)
            if not backup_path:
                tkinter.messagebox.showwarning("警告", "备份创建失败，已取消删除操作！")
                return

            # 执行删除
            self._threaded_delete(delete_files)
        except Exception as e:
            tkinter.messagebox.showerror("错误", f"操作失败: {str(e)}")
    def MenuRestoreBackup(self):
        """恢复备份菜单事件"""
        backup_dir = BackupManager().backup_dir
        if not os.path.exists(backup_dir):
            tkinter.messagebox.showinfo("提示", "暂无备份文件")
            return

        # 弹出备份选择窗口
        selected = tkinter.filedialog.askopenfilename(
            initialdir=backup_dir,
            title="选择要恢复的备份文件",
            filetypes=[("ZIP Files", "*.zip")]
        )
        if not selected:
            return

        # 选择恢复路径
        target_dir = tkinter.filedialog.askdirectory(title="选择恢复目录（默认原始路径）")

        # 执行恢复
        backup = BackupManager()
        success = backup.restore_backup(selected, target_dir if target_dir else None)

        if success:
            tkinter.messagebox.showinfo("成功", "备份恢复完成！")
        else:
            tkinter.messagebox.showerror("失败", "恢复过程中发生错误")
    # "搜索大文件"菜单
    def MenuScanBigFile(self):
        s = tkinter.simpledialog.askinteger('ClearFile', '请设置大文件的大小(M)')
        t = threading.Thread(target=self.ScanBigFile, args=(s,))
        t.start()

    # "按名称搜索文件"菜单
    def MenuSearchFile(self):
        s = tkinter.simpledialog.askstring('ClearFile', '请输入文件名的部分字符')
        t = threading.Thread(target=self.SearchFile, args=(s,))
        t.start()

    def _threaded_delete(self, file_list):
        """后台删除线程"""
        success_count = 0
        backup = BackupManager()

        for file_path in file_list:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)  # 快速删除模式
                    success_count += 1
                    # 更新界面（每删除50个文件刷新一次）
                    if success_count % 50 == 0:
                        self.flist.delete(0.0, tkinter.END)
                        self.flist.insert(tkinter.END, "\n".join(file_list[success_count:]))
            except Exception as e:
                print(f"删除失败: {file_path} - {str(e)}")

        # 清理过期备份
        backup.cleanup_old_backups()

        # 显示结果
        self.progress['text'] = f"成功删除 {success_count}/{len(file_list)} 个文件"

    # 搜索大文件
    def ScanBigFile(self, filesize):
        total = 0
        filesize = filesize * 1024 * 1024
        for drive in GetDrives():
            for root, dirs, files in os.walk(drive):
                for fil in files:
                    try:
                        fname = os.path.abspath(os.path.join(root, fil))
                        fsize = os.path.getsize(fname)
                        self.progress['text'] = fname  # 在状态标签中显示每一个遍历的文件
                        if fsize >= filesize:
                            total += 1
                            self.flist.insert(tkinter.END, '%s，[%.2f M]\n' % (fname, fsize / 1024 / 1024))
                    except:
                        pass
        self.progress['text'] = "找到 %s 个超过 %s M 的大文件" % (total, filesize / 1024 / 1024)

    def SearchFile(self, fname):
        total = 0
        fname = fname.upper()
        for drive in GetDrives():
            for root, dirs, files in os.walk(drive):
                for fil in files:
                    try:
                        fn = os.path.abspath(os.path.join(root, fil))
                        l = len(fn)
                        if l > 50:
                            self.progress['text'] = fn[:25] + '...' + fn[l - 25:l]
                        else:
                            self.progress['text'] = fn
                        if fil.upper().find(fname) >= 0:
                            total += 1
                            self.flist.insert(tkinter.END, fn + '\n')
                    except:
                        pass
        self.progress['text'] = "找到 %s 个文件" % (total)


if __name__ == "__main__":
    window = Window()
    window.MainLoop()