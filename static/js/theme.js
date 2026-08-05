/*
 * theme.js — общие визуальные усиления интерфейса.
 *
 * Ничего здесь не трогает существующую бизнес-логику: только hover/ripple-
 * эффекты, инициализация тултипов/AOS, авто-показ тостов через Bootstrap JS
 * и мобильный тумблер сайдбара. Все существующие обработчики в шаблонах
 * (копирование, поиск, сортировка, автообновление статусов) не изменяются.
 */
(function () {
    "use strict";

    /* --- Копирование в буфер обмена с фолбэком.
       navigator.clipboard требует "secure context" (https или localhost) —
       на панели, открытой по обычному http://IP:8000 (без TLS-сертификата,
       частый случай для самостоятельно установленной VPN-панели), этого
       объекта у браузера просто нет, и копирование молча ничего не делает.
       PanelClipboard.write() пробует современный API, а если он недоступен
       или падает — откатывается на document.execCommand('copy'), который
       работает и по http. Используется всеми inline-скриптами в шаблонах
       (window.PanelClipboard), чтобы не дублировать эту логику. --- */
    window.PanelClipboard = {
        write: function (text) {
            if (navigator.clipboard && window.isSecureContext) {
                return navigator.clipboard.writeText(text).catch(function () {
                    return window.PanelClipboard._fallback(text);
                });
            }
            return window.PanelClipboard._fallback(text);
        },
        _fallback: function (text) {
            return new Promise(function (resolve, reject) {
                var textarea = document.createElement("textarea");
                textarea.value = text;
                textarea.setAttribute("readonly", "");
                textarea.style.position = "fixed";
                textarea.style.top = "-1000px";
                textarea.style.left = "-1000px";
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();
                textarea.setSelectionRange(0, text.length);
                var ok = false;
                try {
                    ok = document.execCommand("copy");
                } catch (err) {
                    ok = false;
                }
                document.body.removeChild(textarea);
                if (ok) {
                    resolve();
                } else {
                    reject(new Error("copy command failed"));
                }
            });
        },
    };

    document.addEventListener("DOMContentLoaded", function () {
        initSidebarToggle();
        initRipple();
        initTooltips();
        initToasts();
        initProgressBar();
        initQrLightbox();
        initAddressWrap();
        initHeroSelector();
    });

    /* --- Верхняя полоса загрузки: показывается на время fetch()/отправки форм.
       Не меняет ни один запрос — просто оборачивает существующий fetch и
       слушает событие submit, чтобы дать визуальную обратную связь. --- */
    var PanelProgress = {
        el: null,
        hideTimer: null,
        showTimer: null,
        pending: 0,
        // Быстрые фоновые опросы (каждые 5-6с) не должны заставлять полосу
        // мигать — показываем её только если запрос реально подвис (>200мс).
        start: function () {
            if (!this.el) return;
            this.pending += 1;
            var self = this;
            window.clearTimeout(this.hideTimer);
            window.clearTimeout(this.showTimer);
            this.showTimer = window.setTimeout(function () {
                if (self.pending <= 0) return;
                self.el.style.transition = "none";
                self.el.style.width = "0%";
                void self.el.offsetWidth;
                self.el.style.transition = "";
                self.el.classList.add("is-active");
                self.el.style.width = "72%";
            }, 200);
        },
        done: function () {
            if (!this.el) return;
            this.pending = Math.max(0, this.pending - 1);
            if (this.pending > 0) return;
            window.clearTimeout(this.showTimer);
            if (!this.el.classList.contains("is-active")) return;
            this.el.style.width = "100%";
            var self = this;
            this.hideTimer = window.setTimeout(function () {
                self.el.classList.remove("is-active");
                self.el.style.width = "0%";
            }, 260);
        },
    };

    function initProgressBar() {
        PanelProgress.el = document.getElementById("panelProgress");
        if (!PanelProgress.el || typeof window.fetch !== "function") return;

        var originalFetch = window.fetch.bind(window);
        window.fetch = function () {
            PanelProgress.start();
            var result = originalFetch.apply(window, arguments);
            result.then(
                function (response) { PanelProgress.done(); return response; },
                function (error) { PanelProgress.done(); throw error; }
            );
            return result;
        };

        document.addEventListener("submit", function (event) {
            var form = event.target;
            if (form && form.tagName === "FORM" && !event.defaultPrevented) {
                PanelProgress.start();
            }
        });
    }

    /* --- Длинные значения без пробелов (домен+порт вроде addons.mozilla.org:8443
       в карточке "Адрес подключения") при переносе ломались посреди слова.
       Расставляем <wbr> после точек/двоеточий — перенос (если нужен) идёт
       по границам, а не абы где. Собирается через DOM API (textContent +
       createElement), без innerHTML — безопасно независимо от содержимого. --- */
    function initAddressWrap() {
        document.querySelectorAll(".stat-value.mono").forEach(function (el) {
            var text = el.textContent;
            if (!text || !/[.:]/.test(text)) return;
            var parts = text.split(/([.:])/);
            el.textContent = "";
            parts.forEach(function (part) {
                el.appendChild(document.createTextNode(part));
                if (part === "." || part === ":") {
                    el.appendChild(document.createElement("wbr"));
                }
            });
        });
    }

    /* --- Крупная QR-карточка вверху страницы WG/VLESS раньше всегда
       показывала только primary_client (по сути — последнее созданное
       устройство), а переключить её на другого, уже существующего
       клиента, было нельзя. Кнопка "Показать крупно" в строке таблицы
       переносит выбранного клиента наверх, в ту же карточку. --- */
    function initHeroSelector() {
        var hero = document.getElementById("heroCard");
        if (!hero) return;
        var urlPrefix = hero.getAttribute("data-url-prefix") || "";

        document.querySelectorAll(".js-select-hero").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var row = btn.closest(".js-client-row");
                if (!row) return;
                selectHeroClient(row);
            });
        });

        function selectHeroClient(row) {
            var id = row.getAttribute("data-client-id");
            var name = row.getAttribute("data-client-name") || "";
            var primary = row.getAttribute("data-client-primary") || "";
            var secondary = row.getAttribute("data-client-secondary") || "";
            var connection = row.getAttribute("data-client-connection") || "";
            var traffic = row.getAttribute("data-client-traffic") || "";
            var qr = row.getAttribute("data-client-qr") || "";

            hero.setAttribute("data-active-client-id", id);

            var nameEl = document.getElementById("heroClientName");
            if (nameEl) nameEl.textContent = name;

            var qrImg = document.getElementById("heroQrImage");
            if (qrImg && qr) {
                qrImg.src = qr;
                qrImg.alt = "QR " + name;
                qrImg.setAttribute("data-qr-caption", name);
            }

            var primaryEl = document.getElementById("heroPrimaryValue");
            if (primaryEl) primaryEl.textContent = primary;

            var connectionEl = document.getElementById("heroConnectionInfo");
            if (connectionEl) {
                connectionEl.textContent = (connection || "нет подключений") + (traffic ? " · " + traffic : "");
            }

            var downloadLink = document.getElementById("heroDownloadLink");
            if (downloadLink) {
                downloadLink.setAttribute("href", urlPrefix + "/peers/" + id + "/download");
            }

            var copyIcon = document.getElementById("heroCopyIcon");
            if (copyIcon) copyIcon.setAttribute("data-copy", secondary);

            document.querySelectorAll(".js-client-row").forEach(function (r) {
                r.classList.remove("is-hero-active");
            });
            row.classList.add("is-hero-active");

            hero.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    }

    /* --- Лайтбокс QR: работает для ЛЮБОГО .qr-thumb на странице (в таблице
       прокси, в таблице устройств WG/VLESS и в hero-карточке), а не только
       для последнего созданного клиента — раньше крупно посмотреть QR
       можно было только у него, у остальных был просто мелкий превью. --- */
    function initQrLightbox() {
        var lightbox = document.getElementById("qrLightbox");
        if (!lightbox) return;
        var img = lightbox.querySelector(".qr-lightbox-img");
        var caption = document.getElementById("qrLightboxCaption");

        function open(src, alt, label) {
            img.src = src;
            img.alt = alt || "QR";
            if (caption) caption.textContent = label || "";
            lightbox.classList.add("is-open");
            lightbox.setAttribute("aria-hidden", "false");
        }
        function close() {
            lightbox.classList.remove("is-open");
            lightbox.setAttribute("aria-hidden", "true");
        }

        document.addEventListener("click", function (event) {
            var trigger = event.target.closest("img.qr-thumb");
            if (trigger) {
                open(trigger.currentSrc || trigger.src, trigger.alt, trigger.getAttribute("data-qr-caption"));
                return;
            }
            // Открытый лайтбокс закрывается кликом в любом месте (включая саму картинку).
            if (lightbox.classList.contains("is-open")) {
                close();
            }
        });
        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape") close();
        });
    }

    /* --- Мобильный сайдбар: открытие/закрытие по кнопке-гамбургеру --- */
    function initSidebarToggle() {
        var toggle = document.getElementById("sidebarToggle");
        var backdrop = document.getElementById("sidebarBackdrop");
        if (!toggle) return;

        function close() {
            document.body.classList.remove("sidebar-open");
        }
        toggle.addEventListener("click", function () {
            document.body.classList.toggle("sidebar-open");
        });
        if (backdrop) backdrop.addEventListener("click", close);

        document.querySelectorAll(".app-sidebar .sidebar-link").forEach(function (link) {
            link.addEventListener("click", close);
        });
    }

    /* --- Лёгкий ripple-эффект на кнопках Bootstrap --- */
    function initRipple() {
        document.addEventListener("click", function (event) {
            var btn = event.target.closest(".btn");
            if (!btn) return;
            var rect = btn.getBoundingClientRect();
            var ripple = document.createElement("span");
            var size = Math.max(rect.width, rect.height);
            ripple.className = "ripple";
            ripple.style.width = ripple.style.height = size + "px";
            ripple.style.left = (event.clientX - rect.left - size / 2) + "px";
            ripple.style.top = (event.clientY - rect.top - size / 2) + "px";
            btn.appendChild(ripple);
            window.setTimeout(function () {
                ripple.remove();
            }, 620);
        });
    }

    /* --- Bootstrap tooltips: активируем только там, где явно проставлен data-bs-toggle="tooltip" --- */
    function initTooltips() {
        if (typeof bootstrap === "undefined" || !bootstrap.Tooltip) return;
        document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
            new bootstrap.Tooltip(el);
        });
    }

    /* --- Тосты: включаем нормальную Bootstrap-анимацию/автоскрытие вместо голого класса show --- */
    function initToasts() {
        if (typeof bootstrap === "undefined" || !bootstrap.Toast) return;
        document.querySelectorAll(".toast.show").forEach(function (el) {
            var toast = new bootstrap.Toast(el, { delay: 6000 });
            toast.show();
        });
    }

})();
