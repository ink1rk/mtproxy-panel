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

    document.addEventListener("DOMContentLoaded", function () {
        initSidebarToggle();
        initRipple();
        initTooltips();
        initToasts();
        initProgressBar();
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
