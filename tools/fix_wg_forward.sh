#!/usr/bin/env bash
# Совместимость: перенаправляем на полный ремонт маршрутизации.
exec bash "$(dirname "$0")/fix_wg_routing.sh" "$@"
