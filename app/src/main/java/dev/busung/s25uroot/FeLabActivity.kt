package dev.busung.s25uroot

import android.os.Build
import android.os.Bundle
import android.system.Os
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.busung.s25uroot.ui.theme.RootMyGalaxyTheme
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * FE Attempt 68 research artifact launcher, NOT a G9810 root exploit.
 * Deliberately does not bypass the HYJ1 target guards or execute the full
 * kernel-mutating path with wrong offsets. It is a launcher + diagnostic probe.
 */
class FeLabActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            RootMyGalaxyTheme(
                accentColor = AppPreferences.accentColor(this),
                themeMode = AppPreferences.themeMode(this),
            ) {
                FeLabScreen()
            }
        }
    }
}

@Composable
private fun FeLabScreen() {
    val scope = rememberCoroutineScope()
    val kernel = remember { runCatching { Os.uname().release }.getOrDefault("unknown") }
    val exactFe = Build.MODEL == "SM-G781W" && kernel == "4.19.113-27223811"
    var accepted by remember { mutableStateOf(false) }
    var running by remember { mutableStateOf(false) }
    var output by remember { mutableStateOf("尚未运行") }

    fun start(dry: Boolean) {
        if (running || (!dry && !accepted)) return
        running = true
        output = "准备通过 Shizuku shell 运行 FE 原版二进制……"
        scope.launch {
            try {
                check(ShizukuController.pingUntilRunning()) {
                    "Shizuku 未启动；请先在 Shizuku 中通过 ADB 启动。"
                }
                check(ShizukuController.requestPermission()) {
                    "未取得 Shizuku 权限。"
                }
                output = withContext(Dispatchers.IO) { FeLabRunner.run(dry) }
            } catch (t: Throwable) {
                output = "失败：${t.message ?: t.javaClass.simpleName}"
            } finally {
                running = false
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { Text("FE GhostLock 实验入口", style = MaterialTheme.typography.headlineSmall) }
        item {
            Text("本机：${Build.MODEL} / $kernel\nFE 原版：SM-G781W / 4.19.113-27223811")
        }
        item {
            Text(
                if (exactFe) "内核和型号初步匹配；仍需完整固件及利用链核验。"
                else "注意：本机与 FE 固件不匹配。此入口不能将 FE 变成可用的 G9810 Root。",
                color = MaterialTheme.colorScheme.error,
            )
        }
        item {
            Text(
                "调用官方研究仓库中的 ionstack_preload.so，下载后校验 SHA-256，" +
                    "再由 Shizuku shell 执行并展示原始日志。不会安装 KernelSU。",
            )
        }
        item {
            OutlinedButton(onClick = { start(true) }, enabled = !running, modifier = Modifier.fillMaxWidth()) {
                Text("一键检查 FE 主程序（不触发漏洞）")
            }
        }
        item {
            Column {
                androidx.compose.foundation.layout.Row {
                    Checkbox(checked = accepted, onCheckedChange = { accepted = it })
                    Text(
                        "我知道 FE 的完整利用链不适用于本机；下面只执行受保护的单阶段试运行，" +
                            "它通常会拒绝继续，不等于 Root。",
                        modifier = Modifier.padding(top = 10.dp),
                    )
                }
                Button(
                    onClick = { start(false) },
                    enabled = !running && accepted,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("一键试运行 FE 的受保护 Root 阶段")
                }
            }
        }
        if (running) item { CircularProgressIndicator() }
        item { Text("执行日志", style = MaterialTheme.typography.titleMedium) }
        item { Text(output, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
        item { Text("说明：真正的 Attempt 68 还需要 HYJ1 专用的前置准备、内核地址和运行时验证材料。") }
    }
}

private object FeLabRunner {
    private const val URL_PATH =
        "https://raw.githubusercontent.com/jojobear691/SM-G781W-HYJ1-GhostLock-Temporary-Root/" +
        "f76e66c52407b401f2bbe380d6c3812fa925c265/artifacts/attempt68/ionstack_preload.so"
    private const val SHA256 = "b72d726e0cb8457bdb311f6a928884bf25f9371346b1b5a600602ccc0b81c4db"
    private const val REMOTE_PATH = "/data/local/tmp/rmg_fe_a68_preload.so"

    suspend fun run(dry: Boolean): String = withContext(Dispatchers.IO) {
        val payload = fetchVerified()
        // Copy through Shizuku: ordinary app UIDs cannot directly write /data/local/tmp.
        ShizukuController.writeFile(REMOTE_PATH, "0600", ByteArrayInputStream(payload))
        val env = buildList {
            add("IONSTACK_STAGE=fops-write-root")
            add("LD_PRELOAD=$REMOTE_PATH")
            if (dry) add("IONSTACK_DRY_OFFSETS=1")
            else add("IONSTACK_FOPS_ROOT_ROUTE=taskwork-native-setexec-shell-root")
        }.toTypedArray()
        val process = ShizukuController.exec(arrayOf("/system/bin/sh", "-c", ":"), env)
        try {
            val stdout = async { process.inputStream.bufferedReader().use { it.readText() } }
            val stderr = async { process.errorStream.bufferedReader().use { it.readText() } }
            val code = withTimeout(25_000) {
                while (process.isAlive) delay(60)
                process.exitValue()
            }
            val allOutput = stdout.await() + stderr.await()
            "FE 单阶段测试（${if (dry) "仅显示固件偏移" else "受保护执行入口"}）\n" +
                "exitCode=$code\n" + allOutput + "\n" +
                "以上输出不代表 Root。请根据日志中的失败原因判断。"
        } finally {
            if (process.isAlive) process.destroy()
        }
    }

    private fun fetchVerified(): ByteArray {
        val connection = (URL(URL_PATH).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 30_000
            instanceFollowRedirects = true
        }
        try {
            check(connection.responseCode == 200) { "下载失败：HTTP ${connection.responseCode}" }
            val bytes = ByteArrayOutputStream().use { target ->
                connection.inputStream.use { source ->
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        target.write(buffer, 0, count)
                        check(target.size() <= 1024 * 1024) { "FE 文件大小异常" }
                    }
                }
                target.toByteArray()
            }
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
            check(digest == SHA256) { "SHA-256 不匹配，拒绝执行" }
            return bytes
        } finally {
            connection.disconnect()
        }
    }
}
