using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

class Native {
 [StructLayout(LayoutKind.Sequential)] public struct FT { public uint Low, High; public ulong Value { get { return ((ulong)High << 32) | Low; } } }
 [DllImport("kernel32.dll")] public static extern bool GetSystemTimes(out FT idle, out FT kernel, out FT user);
 [StructLayout(LayoutKind.Sequential)] public class Memory { public uint Length=64, Load; public ulong Total, Available, PageTotal, PageAvailable, VirtualTotal, VirtualAvailable, Extended; }
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GlobalMemoryStatusEx([In,Out] Memory m);
 public delegate bool WindowCallback(IntPtr h, IntPtr arg);
 [DllImport("user32.dll")] public static extern bool EnumWindows(WindowCallback cb, IntPtr arg);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder text, int max);
 [DllImport("user32.dll", SetLastError=true)] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
}
class Proc {
 public int Id; public string Name, Path; public long Start, Bytes; public double CpuSeconds, Cpu; public bool Protected;
 public List<string> Titles = new List<string>();
}
class AppGroup {
 public string Name {get;set;} public string Display {get;set;} public string Subtitle {get;set;}
 public double Cpu {get;set;} public long Bytes {get;set;} public double MemoryPercent {get;set;}
 public string CpuText {get {return Cpu.ToString("0.0")+"%";}}
 public string MemoryText {get {return Bytes>=1073741824 ? (Bytes/1073741824.0).ToString("0.00")+" GB" : (Bytes/1048576.0).ToString("0")+" MB";}}
 public int Count {get {return Processes.Count;}}
 public ImageSource Icon {get;set;} public List<Proc> Processes = new List<Proc>();
 public bool Protected {get {return Processes.Any(p=>p.Protected);}}
}
class Sample { public double Cpu, Mem; public ulong Total, Available; public List<AppGroup> Groups; }
class Collector {
 Dictionary<int,Proc> previous = new Dictionary<int,Proc>();
 Dictionary<string,ImageSource> icons = new Dictionary<string,ImageSource>(StringComparer.OrdinalIgnoreCase);
 Native.FT lastIdle,lastKernel,lastUser; DateTime lastTime=DateTime.UtcNow;
 static readonly int own=Process.GetCurrentProcess().Id;
 static readonly int session=Process.GetCurrentProcess().SessionId;
 static readonly string win=Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\')+"\\";
 static readonly HashSet<string> reserved = new HashSet<string>(new[]{"system","idle","registry","secure system","memory compression","smss","csrss","wininit","services","lsass","svchost","winlogon","dwm","fontdrvhost","sihost","explorer","shellexperiencehost","startmenuexperiencehost","searchhost","securityhealthservice","msmpeng","nissrv"},StringComparer.OrdinalIgnoreCase);
 public Collector() { Native.GetSystemTimes(out lastIdle,out lastKernel,out lastUser); }
 public static bool IsProtected(Process p, string name, string path) {
  if(p.Id==own || reserved.Contains(name) || String.IsNullOrEmpty(path) || path.StartsWith(win,StringComparison.OrdinalIgnoreCase)) return true;
  try { return p.SessionId!=session; } catch {return true;}
 }
 public static string Label(string name) {
  switch(name.ToLowerInvariant()) {case "code":return "Visual Studio Code";case "msedge":return "Microsoft Edge";case "chrome":return "Google Chrome";case "node":return "Node.js";case "weixin":return "微信";case "wechatappex":return "微信小程序";case "feishu":return "飞书";case "explorer":return "Windows 资源管理器";default:return name;}
 }
 ImageSource GetIcon(string path) {
  if(String.IsNullOrEmpty(path)) return null;
  ImageSource value;
  if(icons.TryGetValue(path,out value)) return value;
  try {using(var icon=System.Drawing.Icon.ExtractAssociatedIcon(path)) {if(icon!=null) {value=Imaging.CreateBitmapSourceFromHIcon(icon.Handle,Int32Rect.Empty,BitmapSizeOptions.FromWidthAndHeight(28,28));value.Freeze();}}} catch {value=null;}
  if(icons.Count<256) icons[path]=value;
  return value;
 }
 public Sample Read() {
  var now=DateTime.UtcNow;double elapsed=Math.Max(0.1,(now-lastTime).TotalSeconds);lastTime=now;
  var mem=new Native.Memory();if(!Native.GlobalMemoryStatusEx(mem)) throw new Exception("无法读取物理内存");
  Native.FT idle,kernel,user;double cpu=0;
  if(Native.GetSystemTimes(out idle,out kernel,out user)) {ulong total=(kernel.Value-lastKernel.Value)+(user.Value-lastUser.Value);if(total>0) cpu=100.0*(1-(idle.Value-lastIdle.Value)/(double)total);lastIdle=idle;lastKernel=kernel;lastUser=user;}
  var current=new Dictionary<int,Proc>();
  foreach(var p in Process.GetProcesses()) {using(p) {try {
   var item=new Proc{Id=p.Id,Name=p.ProcessName,Bytes=p.WorkingSet64};
   try {item.Start=p.StartTime.ToUniversalTime().Ticks;item.CpuSeconds=p.TotalProcessorTime.TotalSeconds;} catch {}
   Proc old; if(previous.TryGetValue(item.Id,out old)&&old.Start==item.Start) {
    item.Path=old.Path;item.Protected=old.Protected;item.Cpu=Math.Max(0,Math.Min(100,(item.CpuSeconds-old.CpuSeconds)/elapsed/Environment.ProcessorCount*100));
   } else {try {item.Path=p.MainModule.FileName;}catch{}item.Protected=IsProtected(p,item.Name,item.Path);}
   current[item.Id]=item;
  }catch{}}}
  Native.EnumWindows(delegate(IntPtr h,IntPtr arg){if(Native.IsWindowVisible(h)){uint pid;Native.GetWindowThreadProcessId(h,out pid);Proc p;if(current.TryGetValue((int)pid,out p)){var b=new StringBuilder(512);Native.GetWindowText(h,b,b.Capacity);if(b.Length>0)p.Titles.Add(b.ToString());}}return true;},IntPtr.Zero);
  previous=current;
  var groups=current.Values.GroupBy(p=>p.Name,StringComparer.OrdinalIgnoreCase).Select(g=> {
   var list=g.ToList();string path=list.Select(p=>p.Path).FirstOrDefault(p=>!String.IsNullOrEmpty(p));
   return new AppGroup{Name=g.Key,Display=Label(g.Key),Subtitle=g.Key+".exe"+(list.Any(p=>p.Protected)?" · 受保护":""),Cpu=list.Sum(p=>p.Cpu),Bytes=list.Sum(p=>p.Bytes),MemoryPercent=Math.Min(100,list.Sum(p=>p.Bytes)/(double)mem.Total*100),Processes=list,Icon=GetIcon(path)};
  }).ToList();
  return new Sample{Cpu=Math.Max(0,Math.Min(100,cpu)),Mem=100*(1-mem.Available/(double)mem.Total),Total=mem.Total,Available=mem.Available,Groups=groups};
 }
 // 在执行动作时重新验证身份，避免 PID 被回收后误操作其他程序。
 public static Process OpenVerified(Proc item) {
  var p=Process.GetProcessById(item.Id);
  try {if(item.Start==0 || p.StartTime.ToUniversalTime().Ticks!=item.Start || p.ProcessName!=item.Name)throw new Exception("进程已变化，已跳过");
   string path=p.MainModule.FileName;if(IsProtected(p,p.ProcessName,path))throw new Exception("系统或受保护进程，已跳过");return p;
  }catch {p.Dispose();throw;}
 }
 public static bool RequestClose(Proc item) {
  using(var p=OpenVerified(item)) {
   bool sent=false;
   Native.EnumWindows(delegate(IntPtr h,IntPtr arg){uint pid;Native.GetWindowThreadProcessId(h,out pid);if(pid==(uint)p.Id && Native.IsWindowVisible(h)) {var b=new StringBuilder(512);Native.GetWindowText(h,b,b.Capacity);if(b.Length>0)sent=Native.PostMessage(h,0x10,IntPtr.Zero,IntPtr.Zero)||sent;}return true;},IntPtr.Zero);
   return sent;
  }
 }
 public static void ForceClose(Proc item) {using(var p=OpenVerified(item))p.Kill();}
}
class Program {
 Window window; Collector collector=new Collector(); DispatcherTimer timer; bool busy,paused,acting,sortCpu; Sample latest;
 DataGrid grid; TextBox search; List<double> cpuHistory=new List<double>(),memHistory=new List<double>();
 T Find<T>(string name) where T:class {return window.FindName(name) as T;}
 void Text(string name,string value) {Find<TextBlock>(name).Text=value;}
 [STAThread] public static void Main(string[] args) {
  if(args.Contains("--test-worker")) {System.Threading.Thread.Sleep(60000);return;}
  if(args.Contains("--self-test")) {SelfTest(args);return;}
  if(args.Contains("--test-child")) {var a=new Application();a.Run(new Window{Title="星脉测试窗口",Width=300,Height=160,Content=new TextBlock{Text="仅用于退出测试",Margin=new Thickness(25)}});return;}
  try {new Program().Run();}catch(Exception e){MessageBox.Show(e.Message,"星脉启动失败");}
 }
 void Run() {
  var app=new Application();using(var s=System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("UI"))window=(Window)XamlReader.Load(s);
  grid=Find<DataGrid>("Apps");search=Find<TextBox>("Search");
  search.TextChanged+=delegate{RefreshList();};grid.SelectionChanged+=delegate{RefreshDetails();};
  Find<Button>("Sort").Click+=delegate{sortCpu=!sortCpu;Find<Button>("Sort").Content=sortCpu?"排序：CPU ↓":"排序：内存 ↓";RefreshList();};
  Find<Button>("Pause").Click+=delegate{paused=!paused;Find<Button>("Pause").Content=paused?"继续":"暂停";Text("Live",paused?"●  已暂停刷新":"●  实时监测 · 每 2 秒");};
  Find<Button>("CloseApp").Click+=delegate{Act(false);};Find<Button>("KillApp").Click+=delegate{Act(true);};
  timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(2)};timer.Tick+=async delegate{await Update();};
  window.Loaded+=async delegate {await Update();timer.Start();};window.Closed+=delegate{timer.Stop();};
  app.Run(window);
 }
 async Task Update() {
  if(busy||paused||acting)return;busy=true;
  try {latest=await Task.Run(()=>collector.Read());if(!window.IsVisible)return;
   Text("CpuValue",latest.Cpu.ToString("0")+"%");Text("CpuInfo",Environment.ProcessorCount+" 逻辑核心");
   Text("MemValue",latest.Mem.ToString("0")+"%");Text("MemInfo",((latest.Total-latest.Available)/1073741824.0).ToString("0.0")+" / "+(latest.Total/1073741824.0).ToString("0.0")+" GB\n可用 "+(latest.Available/1073741824.0).ToString("0.0")+" GB");
   bool high=latest.Mem>=90||latest.Cpu>=85;Text("Health",high?"资源吃紧":latest.Mem>=75||latest.Cpu>=60?"负载较高":"运行从容");
   Find<TextBlock>("Health").Foreground=new SolidColorBrush((Color)ColorConverter.ConvertFromString(high?"#FFBC83":"#54E6CD"));
   Text("Advice",latest.Mem>=90?"内存余量较少，优先查看内存排行榜。":latest.Cpu>=85?"处理器忙碌，优先查看 CPU 排行榜。":"选中暂时不用的软件，查看详情并按需退出。");
   Plot(cpuHistory,latest.Cpu,"CpuLine","CpuPlot");Plot(memHistory,latest.Mem,"MemLine","MemPlot");RefreshList();
   Text("Status","更新于 "+DateTime.Now.ToString("HH:mm:ss")+"  ·  本地运行，无需联网  ·  曲线显示最近约 2 分钟");
  }catch(Exception e){Text("Status","读取失败："+e.Message);}finally{busy=false;}
 }
 void Plot(List<double> data,double v,string line,string host) {data.Add(v);if(data.Count>60)data.RemoveAt(0);double w=Find<Grid>(host).ActualWidth,h=Find<Grid>(host).ActualHeight;var pts=new PointCollection();for(int i=0;i<data.Count;i++)pts.Add(new Point(w*i/59.0,h-3-(h-6)*data[i]/100));Find<Polyline>(line).Points=pts;}
 void RefreshList() {
  if(latest==null)return;string selected=grid.SelectedItem is AppGroup?((AppGroup)grid.SelectedItem).Name:null;
  string q=search.Text.Trim();var filtered=latest.Groups.Where(g=>g.Display.IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0||g.Name.IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0);
  var rows=(sortCpu?filtered.OrderByDescending(g=>g.Cpu).ThenByDescending(g=>g.Bytes):filtered.OrderByDescending(g=>g.Bytes).ThenBy(g=>g.Name)).ToList();
  grid.ItemsSource=rows;if(selected!=null)grid.SelectedItem=rows.FirstOrDefault(g=>g.Name==selected);
  Text("ListInfo",rows.Count+" 个进程组  ·  "+latest.Groups.Sum(g=>g.Count)+" 个进程  ·  同名进程合并显示");RefreshDetails();
 }
 void RefreshDetails() {
  var g=grid.SelectedItem as AppGroup;bool enabled=g!=null&&!g.Protected;
  Find<Button>("KillApp").IsEnabled=enabled;
  Find<Button>("CloseApp").IsEnabled=enabled&&g.Processes.Any(p=>p.Titles.Count>0);
  if(g==null){Text("DetailName","选择一个软件");Text("DetailStats","从左侧列表选择，查看占用与窗口。");Text("Details","");Text("Protection","");return;}
  Text("DetailName",g.Display);Text("DetailStats",g.MemoryText+" 内存  /  "+g.CpuText+" CPU");
  var b=new StringBuilder();b.AppendLine("窗口与进程");foreach(var p in g.Processes.OrderByDescending(p=>p.Bytes)) {b.AppendLine();b.AppendLine("PID "+p.Id+"  ·  "+(p.Bytes/1048576.0).ToString("0")+" MB");foreach(string t in p.Titles)b.AppendLine("› "+t);if(p.Titles.Count==0)b.AppendLine("后台进程 / 无可见窗口");}
  b.AppendLine();b.AppendLine("程序位置");foreach(string path in g.Processes.Select(p=>p.Path).Where(p=>!String.IsNullOrEmpty(p)).Distinct())b.AppendLine(path);
  Text("Details",b.ToString());Text("Protection",g.Protected?"系统、自身、跨会话或身份无法验证的进程组受保护。":g.Processes.Any(p=>p.Titles.Count>0)?"操作将作用于该组当前采样到的进程。":"无可见窗口，无法请求正常退出。强制结束前请确认用途。");
 }
 bool Confirm(AppGroup g,bool force) {
  var dialog=new Window{Owner=window,Title=force?"确认强制结束":"确认正常退出",Width=510,Height=430,ResizeMode=ResizeMode.NoResize,WindowStartupLocation=WindowStartupLocation.CenterOwner,Background=window.Background,Foreground=window.Foreground,FontFamily=window.FontFamily,ShowInTaskbar=false};
  var root=new Grid{Margin=new Thickness(24)};root.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});root.RowDefinitions.Add(new RowDefinition{Height=new GridLength(1,GridUnitType.Star)});root.RowDefinitions.Add(new RowDefinition{Height=GridLength.Auto});
  root.Children.Add(new TextBlock{Text=(force?"强制结束 ":"正常退出 ")+g.Display,FontSize=22,FontWeight=FontWeights.Bold,TextWrapping=TextWrapping.Wrap});
  string titles=String.Join("\n",g.Processes.SelectMany(p=>p.Titles).Select(t=>"• "+t));if(titles.Length==0)titles="此组没有可见窗口。";
  var body=new TextBlock{Text=(force?"未保存的内容可能丢失。将结束当前列出的 "+g.Count+" 个进程，不自动追踪新进程。":"将向以下可见窗口请求关闭，请先保存工作。软件可能弹出保存提示，也可能继续驻留后台。")+"\n\n"+titles+"\n\n进程 ID："+String.Join(", ",g.Processes.Select(p=>p.Id))+"\n\n同名程序可能包含多个独立任务，请仔细核对。",TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,18,0,12),Foreground=new SolidColorBrush(Color.FromRgb(180,197,220))};
  var sc=new ScrollViewer{Content=body,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};Grid.SetRow(sc,1);root.Children.Add(sc);
  var buttons=new StackPanel{Orientation=Orientation.Horizontal,HorizontalAlignment=HorizontalAlignment.Right};var cancel=new Button{Content="取消",MinWidth=95,IsCancel=true,Style=window.FindResource(typeof(Button)) as Style,Margin=new Thickness(0,0,10,0)};cancel.Click+=delegate{dialog.DialogResult=false;};var ok=new Button{Content=force?"确认强制结束":"确认请求退出",MinWidth=130,Style=window.FindResource(typeof(Button)) as Style,Background=new SolidColorBrush(Color.FromRgb(force?(byte)116:(byte)25,force?(byte)46:(byte)97,force?(byte)65:(byte)107))};ok.Click+=delegate{dialog.DialogResult=true;};buttons.Children.Add(cancel);buttons.Children.Add(ok);Grid.SetRow(buttons,2);root.Children.Add(buttons);dialog.Content=root;return dialog.ShowDialog()==true;
 }
 async void Act(bool force) {
  var g=grid.SelectedItem as AppGroup;if(g==null||g.Protected||acting)return;acting=true;
  try {if(!Confirm(g,force))return;
   string result=await Task.Run(()=> {int done=0,skipped=0,failed=0;foreach(var p in g.Processes) {try {if(force){Collector.ForceClose(p);done++;}else if(Collector.RequestClose(p))done++;else skipped++;}catch(ArgumentException){skipped++;}catch(InvalidOperationException){skipped++;}catch{failed++;}}
    return force?"已提交结束 "+done+" 个进程；跳过 "+skipped+"，失败或受保护 "+failed+"。":"已向 "+done+" 个进程发送关闭请求；无窗口或已退出 "+skipped+"，失败或受保护 "+failed+"。请处理软件的保存提示；后台进程可能仍在运行。";});
   MessageBox.Show(window,result,"操作结果",MessageBoxButton.OK,MessageBoxImage.Information);
  }finally {acting=false;}
  await Update();
 }
 static void SelfTest(string[] args) {
  string log=args.Length>1?args[1]:"self-test.txt";var lines=new List<string>();
  try {var c=new Collector();c.Read();System.Threading.Thread.Sleep(1100);var s=c.Read();if(s.Total==0||s.Groups.Count<1||s.Cpu<0||s.Cpu>100)throw new Exception("数据采集异常");lines.Add("数据采集通过，进程组="+s.Groups.Count+" CPU="+s.Cpu.ToString("0.0"));
   var self=s.Groups.SelectMany(g=>g.Processes).First(p=>p.Id==Process.GetCurrentProcess().Id);if(!self.Protected)throw new Exception("自身保护失败");bool blocked=false;try {using(var p=Collector.OpenVerified(self)) {}}catch{blocked=true;}if(!blocked)throw new Exception("动作保护失败");lines.Add("自身与动作前保护通过");
   using(var stream=System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("UI")){var w=(Window)XamlReader.Load(stream);if(w.FindName("Apps")==null)throw new Exception("界面缺失");w.Close();}lines.Add("XAML 界面加载通过");
   using(var child=Process.Start(new ProcessStartInfo(System.Reflection.Assembly.GetExecutingAssembly().Location,"--test-child"){UseShellExecute=false})) {
    try {for(int i=0;i<50;i++){child.Refresh();if(child.MainWindowHandle!=IntPtr.Zero)break;System.Threading.Thread.Sleep(100);}
     var target=new Proc{Id=child.Id,Name=child.ProcessName,Start=child.StartTime.ToUniversalTime().Ticks};
     if(!Collector.RequestClose(target)||!child.WaitForExit(5000))throw new Exception("正常退出测试失败");lines.Add("正常退出测试通过（专用测试窗口）");
    }finally {if(!child.HasExited)child.Kill();}
   }
   using(var child=Process.Start(new ProcessStartInfo(System.Reflection.Assembly.GetExecutingAssembly().Location,"--test-worker"){UseShellExecute=false,CreateNoWindow=true})) {
    try {var target=new Proc{Id=child.Id,Name=child.ProcessName,Start=child.StartTime.ToUniversalTime().Ticks};
     var wrong=new Proc{Id=target.Id,Name=target.Name,Start=target.Start+1};bool denied=false;try{using(var p=Collector.OpenVerified(wrong)){}}catch{denied=true;}if(!denied)throw new Exception("身份校验失败");lines.Add("进程身份变更拦截通过");
     Collector.ForceClose(target);if(!child.WaitForExit(5000))throw new Exception("强制结束测试失败");lines.Add("强制结束测试通过（专用测试进程）");
    }finally {if(!child.HasExited)child.Kill();}
   }
   var preview=new Program();using(var stream=System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("UI"))preview.window=(Window)XamlReader.Load(stream);
   preview.grid=preview.Find<DataGrid>("Apps");preview.search=preview.Find<TextBox>("Search");preview.latest=s;preview.RefreshList();preview.grid.SelectedIndex=0;preview.RefreshDetails();
   preview.Text("CpuValue",s.Cpu.ToString("0")+"%");preview.Text("CpuInfo",Environment.ProcessorCount+" 逻辑核心");preview.Text("MemValue",s.Mem.ToString("0")+"%");preview.Text("MemInfo",((s.Total-s.Available)/1073741824.0).ToString("0.0")+" / "+(s.Total/1073741824.0).ToString("0.0")+" GB\n可用 "+(s.Available/1073741824.0).ToString("0.0")+" GB");preview.Text("Health",s.Mem>=90?"资源吃紧":"实时监测中");preview.Text("Advice","选中暂时不用的软件，查看详情并按需退出。");
   preview.window.ShowActivated=false;preview.window.ShowInTaskbar=false;preview.window.Show();preview.window.UpdateLayout();preview.window.Dispatcher.Invoke(DispatcherPriority.ContextIdle,new Action(delegate{}));
   var root=(FrameworkElement)preview.window.Content;root.UpdateLayout();
   // 预览使用真实采样数据；曲线留空，不生成虚构历史。
   var visual=new DrawingVisual();using(var dc=visual.RenderOpen()) {dc.DrawRectangle(preview.window.Background,null,new Rect(0,0,root.ActualWidth,root.ActualHeight));dc.DrawRectangle(new VisualBrush(root),null,new Rect(0,0,root.ActualWidth,root.ActualHeight));}
   var bitmap=new RenderTargetBitmap((int)root.ActualWidth,(int)root.ActualHeight,96,96,PixelFormats.Pbgra32);bitmap.Render(visual);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));
   using(var file=File.Create(System.IO.Path.Combine(System.IO.Path.GetDirectoryName(log),"preview.png")))encoder.Save(file);preview.window.Close();lines.Add("界面预览已渲染");
   lines.Add("PASS");
  }catch(Exception e){lines.Add("FAIL: "+e.ToString());Environment.ExitCode=1;}File.WriteAllLines(log,lines,Encoding.UTF8);
 }
}
