from user_agents import parse
from ipware import get_client_ip
import logging

logger = logging.getLogger(__name__)


def get_device_info(request):
    """リクエストからデバイス情報を取得"""
    user_agent_string = request.META.get('HTTP_USER_AGENT', '')
    user_agent = parse(user_agent_string)
    
    # デバイスタイプの判定
    if user_agent.is_mobile:
        device_type = 'mobile'
    elif user_agent.is_tablet:
        device_type = 'tablet'
    else:
        device_type = 'desktop'
    
    # デバイス名の生成
    device_parts = []
    if user_agent.device.family and user_agent.device.family != 'Other':
        device_parts.append(user_agent.device.family)
    if user_agent.os.family and user_agent.os.family != 'Other':
        device_parts.append(user_agent.os.family)
        if user_agent.os.version_string:
            device_parts.append(user_agent.os.version_string)
    
    device_name = ' '.join(device_parts) if device_parts else 'Unknown Device'
    
    # ブラウザ情報
    browser = f"{user_agent.browser.family}"
    if user_agent.browser.version_string:
        browser += f" {user_agent.browser.version_string}"
    
    # OS情報
    os = user_agent.os.family
    if user_agent.os.version_string:
        os += f" {user_agent.os.version_string}"
    
    return {
        'device_type': device_type,
        'device_name': device_name,
        'browser': browser,
        'os': os,
        'user_agent': user_agent_string,
    }


def get_location_info(request):
    """IPアドレスから位置情報を取得"""
    client_ip, is_routable = get_client_ip(request)
    
    if not client_ip:
        return {
            'ip_address': '0.0.0.0',
            'city': '不明',
            'country': '不明',
        }
    
    # ローカルIPの場合
    if not is_routable or client_ip.startswith('192.168.') or client_ip.startswith('127.'):
        return {
            'ip_address': client_ip,
            'city': 'ローカル',
            'country': '日本',
        }
    
    # 実際の位置情報取得（GeoIP2を使用する場合）
    # ここでは簡易版として固定値を返す
    # 実装する場合は geoip2 ライブラリを使用
    try:
        # import geoip2.database
        # reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')
        # response = reader.city(client_ip)
        # city = response.city.name or '不明'
        # country = response.country.name or '不明'
        pass
    except Exception as e:
        logger.error(f"GeoIP lookup failed: {e}")
    
    return {
        'ip_address': client_ip,
        'city': '不明',  # 実際の実装ではGeoIPから取得
        'country': '日本',  # 実際の実装ではGeoIPから取得
    }
