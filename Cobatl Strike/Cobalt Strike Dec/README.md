# CS_Dec
## 一、工具介绍

用于解密 Cobalt Strike 的通讯流量。代码源自 [DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite)  和 [WBGlIl/CS_Decrypt](https://github.com/WBGlIl/CS_Decrypt)，进行了一些简单修改。

## 二、使用教程

### 2.1 安装与使用

- 脚本基于 Python3，请确保已在 Windows 的环境变量中正确配置 Python3：

  ![image-20251120192844335](./笔记图片/image-20251120192844335.png)

- 先安装依赖，然后直接执行 `CS_Dec.bat` 即可：

  ![image-20251120182036394](./笔记图片/image-20251120182036394.png)

### 2.2 运行截图

1. Checksum8 规则检查：

   ![image-20251120183734599](./笔记图片/image-20251120183734599.png)

2. 解析 Beacon 程序配置：

   ![image-20251120184525198](./笔记图片/image-20251120184525198.png)

3. 解密 Beacon 元数据：

   ![image-20251120190024068](./笔记图片/image-20251120190024068.png)

4. 解密 C2 服务器下发的任务：

   ![image-20251120185036090](./笔记图片/image-20251120185036090.png)

   ![image-20251120190544328](./笔记图片/image-20251120190544328.png)

5. 解密受控端返回的结果：

   ![image-20251120185247702](./笔记图片/image-20251120185247702.png)

   ![image-20251120185331891](./笔记图片/image-20251120185331891.png)

   ![image-20251120185407471](./笔记图片/image-20251120185407471.png)

6. 提取 `.cobaltstrike.beacon_keys` 文件公私钥：

   ![image-20251120185526954](./笔记图片/image-20251120185526954.png)



