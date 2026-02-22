from __future__ import annotations

from dataclasses import dataclass

from .models import FeatureVector


@dataclass(slots=True)
class RiskResult:
    score: float
    level: str
    reasons: list[str]


class RuleBasedRiskEngine:
    """Weighted risk scoring engine suitable as baseline before full ML models."""

    def evaluate(self, features: FeatureVector, ioc_matches: list[str] | None = None) -> RiskResult:
        ioc_matches = ioc_matches or []

        score = 0.0
        reasons: list[str] = []

        if features.suspicious_permissions_count >= 3:
            score += 28
            reasons.append("Multiples permisos de alto riesgo detectados")
        elif features.suspicious_permissions_count > 0:
            score += 14
            reasons.append("Permisos de alto riesgo presentes")

        if features.overlay_permission_detected:
            score += 10
            reasons.append("Permiso de superposicion detectado (SYSTEM_ALERT_WINDOW)")

        if features.accessibility_binding_detected:
            score += 14
            reasons.append("Capacidad de binding de servicio de accesibilidad")

        if features.install_packages_permission_detected:
            score += 12
            reasons.append("Capacidad de instalar paquetes detectada")

        if features.write_settings_detected:
            score += 10
            reasons.append("Capacidad de modificar ajustes del sistema")

        if features.boot_receiver_detected:
            score += 8
            reasons.append("Persistencia potencial al arranque detectada")

        if features.ad_sdk_hits >= 4:
            score += 15
            reasons.append("Alta densidad de librerias SDK de anuncios/tracking")
        elif features.ad_sdk_hits > 0:
            score += 6
            reasons.append("Presencia de SDK de anuncios/tracking")

        if features.tracker_hits >= 3:
            score += 10
            reasons.append("Multiples indicadores de tracking en metadatos")
        elif features.tracker_hits > 0:
            score += 5
            reasons.append("Indicadores de tracking en metadatos")

        if features.suspicious_keyword_hits >= 2:
            score += 6
            reasons.append("Keywords sensibles detectadas en informacion de paquete")

        if features.dangerous_permissions_count >= 8:
            score += 12
            reasons.append("Superficie de permisos peligrosos muy alta")
        elif features.dangerous_permissions_count >= 4:
            score += 6
            reasons.append("Superficie de permisos peligrosos elevada")

        if ioc_matches:
            score += min(32.0, 8.0 * len(ioc_matches))
            reasons.append(f"Coincidencias IOC activas: {len(ioc_matches)}")

        if "unknown" in features.installer.lower() or not features.installer.strip():
            score += 6
            reasons.append("Instalador desconocido o no confiable")

        score = min(100.0, round(score, 2))
        level = self._score_to_level(score)
        return RiskResult(score=score, level=level, reasons=reasons)

    @staticmethod
    def _score_to_level(score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 55:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"
