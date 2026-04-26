/**
 * 长安 UNI-V 精简状态通知脚本（当天第一次 + 安全/电压变化触发）
 */
let body = $response.body;
let cacheKey = "changan_last_key_status";
let dateKey = "changan_last_notify_date"; // 用于记录当天日期

if (body) {
    try {
        let obj = JSON.parse(body);
        if (obj.code === 0 && obj.success && obj.data) {
            let d = obj.data;

            // 核心状态
            let engineStatus = d.engineStatus === 2 ? "已启动" : "已熄火";
            let mileage = d.totalOdometer;
            let remainMile = d.remainedOilMile;
            let fuel = d.remainingFuel;
            let vol = d.batteryVoltage; 
            let tempIn = d.vehicleTemperature;
            let tempOut = d.environmentalTemp;
            let waterTemp = d.engineWaterTemp;
            let consumption = d.fuelConsumption100km;
            let lf = (d.lfTyrePressure / 100).toFixed(2);
            let rf = (d.rfTyrePressure / 100).toFixed(2);
            let lr = (d.lrTyrePressure / 100).toFixed(2);
            let rr = (d.rrTyrePressure / 100).toFixed(2);

            // 安全状态
            let doors = [d.leftFrontDoor, d.rightFrontDoor, d.leftRearDoor, d.rightRearDoor];
            let windows = [d.leftFrontDoorrWindow, d.rightFrontDoorrWindow, d.leftRearWindow, d.rightRearWindow, d.sunroof];
            let locks = [d.leftFrontDoorLock, d.rightFrontDoorLock, d.leftRearDoorLock, d.rightRearDoorLock];
            let trunkHood = [d.trunk, d.hood];

            let isDoorsClosed = doors.every(v => v === 0);
            let isWindowsClosed = windows.every(v => v === 0);
            let isLocksClosed = locks.every(v => v === 0);
            let isTrunkHoodClosed = trunkHood.every(v => v === 0);

            let securityStatus = [];
            if (!isDoorsClosed) securityStatus.push("车门未全关");
            if (!isWindowsClosed) securityStatus.push("车窗/天窗未关");
            if (!isLocksClosed) securityStatus.push("车门未落锁");
            if (!isTrunkHoodClosed) securityStatus.push("引擎盖/后备箱未关");
            let securityStr = securityStatus.length > 0 ? securityStatus.join(" | ") : "全车锁闭良好 🛡️";

            // 构造关键状态对象
            let currentKeyStatus = { vol, securityStr };

            // 获取历史状态和日期
            let lastStatusRaw = $prefs.valueForKey(cacheKey);
            let lastStatus = lastStatusRaw ? JSON.parse(lastStatusRaw) : null;
            let lastDate = $prefs.valueForKey(dateKey) || "";
            let today = new Date().toISOString().split("T")[0];

            let changed = !lastStatus || JSON.stringify(lastStatus) !== JSON.stringify(currentKeyStatus);
            let pushNotification = false;

            if (lastDate !== today) {
                pushNotification = true;  // 当天第一次访问，总是推送
                $prefs.setValueForKey(today, dateKey);
            } else if (changed) {
                pushNotification = true;  // 当天非第一次访问，状态变化才推送
            }

            if (pushNotification) {
                $prefs.setValueForKey(JSON.stringify(currentKeyStatus), cacheKey);

                let title = `🚗 UNI-V 状态 [${engineStatus}]`;
                let subtitle = `⛽ 油量: ${fuel}% (续航 ${remainMile} km) | 🔋 电瓶: ${vol}V`;
                let detail =
`🌡️ 温度: 车内 ${tempIn}°C / 车外 ${tempOut}°C / 水温 ${waterTemp}°C
📊 行驶: 总里程 ${mileage} km / 综合油耗 ${consumption} L/100km
🛞 胎压: 前 ${lf} / ${rf} Bar | 后 ${lr} / ${rr} Bar
🔒 安防: ${securityStr}
⏱️ 更新时间: ${d.deviceTime}`;

                $notify(title, subtitle, detail);
            }
        }
    } catch (e) {
        console.log("长安车辆数据解析异常: " + e);
    }
}

$done({ body });
