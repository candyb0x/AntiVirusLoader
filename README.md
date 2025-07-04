# AntiVirusLoader
本项目收集并实现了多种常见的 Windows 进程注入与代码执行技术，适用于安全研究、攻防演练与反病毒技术分析。每个子目录为一种独立的注入方式，均配有完整的C++源码实现。

## 目录结构
- APCInjection ：APC（异步过程调用）注入
- BypassSession0Injection ：ZwCreateThreadEx注入，绕过Session 0隔离
- CreateRemoteThread ：远程线程注入
- EarlyBird ：EarlyBird免杀APC注入
- MappingInjection ：物理内存映射注入
- SEHCodeExecute ：SEH异常处理代码执行
- SetContextHijackThread ：线程上下文劫持注入
- TLSCodeExecute ：TLS回调执行
- CustomWinApi ：自定义API调用辅助模块
- 以下是对每种免杀技术实现原理、步骤及免杀思路的详细介绍：

## 1. APCInjection（APC注入）
实现步骤：

1. 获取目标进程PID与线程TID。

2. 动态获取OpenProcess、VirtualAllocEx、WriteProcessMemory、OpenThread、QueueUserAPC等API地址。

3. 打开目标进程，分配可执行内存，写入shellcode。

4. 打开目标线程，使用QueueUserAPC将shellcode地址插入APC队列。

5. 线程恢复后执行shellcode。 

免杀思路：
- 动态解析API，避免静态查杀。
- shellcode可加密存储，运行时解密。
- 选择非典型进程和线程，降低检测概率。
## 2. BypassSession0Injection（ZwCreateThreadEx注入）
实现步骤：

1. 动态获取ZwCreateThreadEx等API。

2. 打开目标进程，远程分配内存并写入shellcode。

3. 调用ZwCreateThreadEx在目标进程中创建线程执行shellcode。 

免杀思路：
- 使用ZwCreateThreadEx绕过Session 0隔离，适用于服务进程注入。
- 动态API调用，shellcode加密。
## 3. CreateRemoteThread（远程线程注入）
实现步骤：

1. 获取目标进程PID。

2. 动态获取OpenProcess、VirtualAllocEx、WriteProcessMemory、CreateRemoteThread等API。

3. 写入并解密shellcode。

4. 调用CreateRemoteThread执行shellcode。 

免杀思路：
- shellcode加密存储，运行时解密。
- 动态API调用，规避静态查杀。
## 4. EarlyBird（EarlyBird免杀APC注入）
实现步骤：

1. 创建挂起的白进程（如notepad.exe）。

2. 分配内存写入shellcode，初始权限为RW。

3. 写入后将内存权限改为NOACCESS，休眠一段时间。

4. 注入前恢复为RX权限。

5. 使用APC注入shellcode，恢复主线程。 

免杀思路：
- 利用进程初始化早期时机，杀软尚未介入。
- 内存权限动态切换，规避内存扫描。
- 结合APC注入，提升隐蔽性。
## 5. MappingInjection（物理内存映射注入）
实现步骤：

1. 创建物理内存映射（CreateFileMappingW）。

2. 本地映射写入shellcode。

3. 创建目标进程（挂起），MapViewOfFile2将映射区映射到目标进程。

4. 使用APC注入shellcode，恢复线程。 

免杀思路：
- 利用物理内存映射实现跨进程共享，规避常规内存分配检测。
- shellcode可加密，动态解密。
## 6. SEHCodeExecute（SEH异常处理代码执行）
实现步骤：

1. 设置SEH异常处理回调。

2. 在异常回调中动态获取VirtualAlloc，分配可执行内存并写入shellcode。

3. 触发异常（如除零），执行shellcode。 

免杀思路：
- 利用异常机制执行，规避常规流程检测。
- 动态API调用，shellcode加密。
## 7. SetContextHijackThread（线程上下文劫持）
实现步骤：

1. 创建目标进程（挂起）。

2. 分配内存写入shellcode。

3. 获取主线程上下文，修改EIP/RIP指向shellcode。

4. 恢复线程。 

免杀思路：
- 劫持线程上下文，绕过常规注入检测。
- 动态API调用。
## 8. TLSCodeExecute（TLS回调执行）
实现步骤：

1. 定义TLS回调函数，shellcode在DLL_PROCESS_ATTACH时执行。

2. 链接器指令将回调注册到TLS段。

3. 程序启动时自动执行shellcode。 

免杀思路：
- 利用TLS机制，进程初始化阶段执行，杀软难以拦截。
- 可与其他技术组合提升隐蔽性。
如需进一步技术细节或代码讲解，可指定具体模块。