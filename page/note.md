# note

{% stepper %}
{% step %}
### 一、下载工具

#### 1. 下载 IDA

这个我直接去52pojie上找然后下载的

#### 2. 下载 x64dbg

去谷歌搜索x64dbg，进入官网https://x64dbg.com/， 然后点击下载就完事儿了！

对了，还有一个重要的工具就是AI，我都是问AI告诉我怎么做的。准备完毕，开始着手吧！
{% endstep %}

{% step %}
### 二、用IDA进行静态分析

{% hint style="info" %}
PS: 注意，这里说一下IDA是干啥的：IDA 是一个：静态分析工具，它不运行程序，只分析代码结构。我们可以用它来看函数逻辑、找关键字符串、看流程图（程序结构）从而来进行逆向分析。
{% endhint %}

打开IDA —> 点击 ok —> 点击 new，开始新项目，找到要分析的文件 crackme.exe 并打开（也可以直接拖进去），会弹出 load a new file 的弹窗，直接点 ok，等待其自动分析完毕，页面下方 output 框会显示：`The initial autoanalysis has been finished.` 就是初步分析完毕。

直接进入眼帘的就是一个流程图一样的页面即反汇编视图，\
![](/broken/files/4YCUNlKnnvjARNAJkJe2)

按住 `shift`+`f12`，打开字符串窗口，找到类似 "Correct"、"Wrong"、"Success"、"Fail"、"Password" 的字眼，双击\
![](/broken/files/APz29R8Ghcn6WwawPhJj)

双击之后进入，可以看到这一行：`rdata:00440043 aWrongTryAgian db 'wrong! try agian! ',0`\
按 `x键`，看看是哪里引用\
![](/broken/files/VWXehTAkDaF8dYefSYtz)

按下 `x键` 之后，可能跳转到反汇编图形视图或者是反汇编列表视图，如果跳转到图形视图可以按下空格键看列表视图\
\
![](/broken/files/bVolKRwUaOFDRJ4bOmud)

<figure><img src="/broken/files/2ByT1ctuGSmFW9In10DK" alt=""><figcaption></figcaption></figure>

在列表视图中，可以看到这个位置：

```asm
.text:004015AF loc_4015AF:                             ; CODE XREF: _main+1F7↑j

.text:004015AF                 mov     [esp+0C8h+var_C4], offset aWrongTryAgian ; "wrong! try agian! "
```

这个地方就是输入错误密码弹出“wrong! try agian!”之处，那么我们往上找就能找到对比密码判断输入密码正确与否的地方：`.text:00401587 jz short loc_4015AF`，记住这个地址：`00401587`\
![](/broken/files/zpZVW7nekA0CX7QecRQ5)

按下 `F5`，看其伪代码\
![](/broken/files/kFjXQfGaLgZ7TeiYTddh)

我们就可以看到,以下代码：

```c
if ( (unsigned __int8)std::operator==<char>((std::string *)v14, (std::string *)v15) )
    v5 = std::operator<<<std::char_traits<char>>((int)&std::cout, "congratulation! ");
  else
    v5 = std::operator<<<std::char_traits<char>>((int)&std::cout, "wrong! try agian! ");
```

按照我的理解，意思就是将正确密码与输入密码进行对比，如果正确就打印 "congratulation! "，如果错误就打印 "wrong! try agian! "。同义，在上面反汇编视图里面 `00401587` 这个地方就是对比密码（正确就跳转到 "congratulation! "，错误就跳转 "wrong! try agian! "）的地方。

PS:\
je = 相等跳\
jne = 不等跳\
jz = 等于0跳\
jnz = 不等于0跳

那么，`.text:00401587 jz short loc_4015AF` 意思就是当等于0时就跳转到 `loc_4015AF`, 那我们就把 `jz` 改成 `jnz`，那不就是无论你输入什么都不跳到 "wrong! try agian!"，而是跳到 "congratulation! " 了吗！
{% endstep %}

{% step %}
### 三、用x64dbg进行动态调试

既然知道了可能破解的地方，我们就到 x64dbg 里面进行动态调试，试试看到底能不能这样干。

#### 1、动态调试

这个 crack.exe 是 32 位的，我们就打开 x32dbg，把它拖进去，按下 `CTRL`+`G`，输入我们在 IDA 找到的那个需要改动的目标的地址，即 `00401587`\
\
![](/broken/files/lJpf0EuT1CVT3pspymY4)

点击这一行 `00401587 | 74 26 | je crackme.4015AF |`，按下空格键（或是鼠标右键点选汇编），将弹框中的 `jz 0x004015AF` 改为 `jnz 0x004015AF` 或是 `nop`，点击 `确定`\
![](/broken/files/kN1BOpvqmEZWwbPJy4RN)

要注意的是改了之后会继续弹框，给下一个地址进行修改，这时候要点击 `取消`\
![](/broken/files/BFtNiVhMd8Zc97EG9W2Z)

改后，点击 `运行`(或者按 `F9` 运行)，随机输入用户名和密码，看看效果\
![](/broken/files/eWfFRaoDvDVn1IaCQm5N)\
![](/broken/files/YALBVgWgO5mkpgLIyQh6)

显示 "congratulation! " 就是成功破解了！但是！这只是在 x32dbg 里调试运行的结果，而不是真正的破解，关掉 x32dbg 之后再打开 crack.exe，随机输入用户名和密码依旧会显示 "wrong! try agian! "。那么，我们接下去就给它打个补丁，真正破解它。

#### 2、打补丁

鼠标右键，点击 `补丁`，会弹出补丁弹框，点击 `修补文件`，会弹出保存文件，取名为 crack\_patched.exe\
![](/broken/files/10mpR2QvBF19TQSuuUxi)

现在，你关掉 x32dbg，打开 crack\_patched.exe，随机输入用户名和密码，都会显示 "congratulation! "\
就这样大功告成，零代码基础的你就成功破解了这个 crack.exe，非常简单！
{% endstep %}
{% endstepper %}
