from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
import secrets
import string
import pyotp

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('メールアドレスは必須です')
        if not username:
            raise ValueError('ユーザー名は必須です')
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('スーパーユーザーはis_staff=Trueである必要があります')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('スーパーユーザーはis_superuser=Trueである必要があります')
        
        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractUser):
    # usernameはログイン用のID（英数字のみ）
    username = models.CharField(
        'ユーザーID',
        max_length=150,
        unique=True,
        help_text='ログイン用のID（英数字、@/./+/-/_のみ使用可能）'
    )
    
    # nicknameは表示用の名前（日本語OK）
    nickname = models.CharField(
        'ニックネーム',
        max_length=50,
        blank=True,
        help_text='表示用の名前（未設定の場合はユーザーIDが表示されます）'
    )
    
    email = models.EmailField('メールアドレス', unique=True)
    phone_number = models.CharField('電話番号', max_length=15, blank=True)
    profile_image = models.ImageField('プロフィール画像', upload_to='profile_images/', null=True, blank=True)
    bio = models.TextField('自己紹介', max_length=500, blank=True)
    created_at = models.DateTimeField('登録日時', auto_now_add=True)
    updated_at = models.DateTimeField('更新日時', auto_now=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'username'  # ログインに使用するフィールド
    REQUIRED_FIELDS = ['email']  # createsuperuserで要求される追加フィールド
    
    class Meta:
        verbose_name = 'ユーザー'
        verbose_name_plural = 'ユーザー'
    
    def __str__(self):
        return self.username
    
    def get_display_name(self):
        """表示名を取得（ニックネームがあればニックネーム、なければユーザー名）"""
        return self.nickname if self.nickname else self.username

# ログイン履歴モデル
class LoginHistory(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='login_history')
    ip_address = models.GenericIPAddressField('IPアドレス')
    user_agent = models.TextField('ユーザーエージェント')
    device_type = models.CharField('デバイスタイプ', max_length=50)  # desktop, mobile, tablet
    device_name = models.CharField('デバイス名', max_length=200)
    browser = models.CharField('ブラウザ', max_length=100)
    os = models.CharField('OS', max_length=100)
    location_city = models.CharField('都市', max_length=100, blank=True)
    location_country = models.CharField('国', max_length=100, blank=True)
    status = models.CharField('ステータス', max_length=20, choices=[
        ('success', '成功'),
        ('failed', '失敗'),
    ])
    timestamp = models.DateTimeField('日時', auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'ログイン履歴'
        verbose_name_plural = 'ログイン履歴'
    
    def __str__(self):
        return f"{self.user.username} - {self.timestamp}"


# アクティブセッションモデル
class ActiveSession(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='active_sessions')
    session_key = models.CharField('セッションキー', max_length=40, unique=True)
    ip_address = models.GenericIPAddressField('IPアドレス')
    user_agent = models.TextField('ユーザーエージェント')
    device_type = models.CharField('デバイスタイプ', max_length=50)
    device_name = models.CharField('デバイス名', max_length=200)
    browser = models.CharField('ブラウザ', max_length=100)
    os = models.CharField('OS', max_length=100)
    location_city = models.CharField('都市', max_length=100, blank=True)
    location_country = models.CharField('国', max_length=100, blank=True)
    created_at = models.DateTimeField('作成日時', auto_now_add=True)
    last_activity = models.DateTimeField('最終アクティビティ', auto_now=True)
    is_current = models.BooleanField('現在のセッション', default=False)
    
    class Meta:
        ordering = ['-last_activity']
        verbose_name = 'アクティブセッション'
        verbose_name_plural = 'アクティブセッション'
    
    def __str__(self):
        return f"{self.user.username} - {self.device_name}"


# WebAuthn認証情報モデル
class WebAuthnCredential(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.TextField('認証情報ID', unique=True)
    public_key = models.TextField('公開鍵')
    sign_count = models.IntegerField('署名カウント', default=0)
    device_name = models.CharField('デバイス名', max_length=200)
    device_type = models.CharField('デバイスタイプ', max_length=50, choices=[
        ('platform', 'プラットフォーム認証'),  # Windows Hello, Touch ID, Face ID
        ('cross-platform', 'クロスプラットフォーム'),  # USB/NFC/BLE セキュリティキー
    ])
    created_at = models.DateTimeField('登録日時', auto_now_add=True)
    last_used = models.DateTimeField('最終使用日時', null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'WebAuthn認証情報'
        verbose_name_plural = 'WebAuthn認証情報'
    
    def __str__(self):
        return f"{self.user.username} - {self.device_name}"


class WebAuthnChallenge(models.Model):
    """WebAuthn チャレンジ"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='webauthn_challenges')
    challenge = models.CharField(max_length=255)
    challenge_type = models.CharField(
        max_length=20,
        choices=[
            ('registration', 'パスキー登録'),
            ('authentication', 'パスキー認証'),
        ],
        default='registration'
    )
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'WebAuthn チャレンジ'
        verbose_name_plural = 'WebAuthn チャレンジ'
    
    def __str__(self):
        return f"Challenge - {self.user.username} ({self.get_challenge_type_display()})"



class TOTPDevice(models.Model):
    """TOTP デバイス（Google Authenticator対応）"""
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='totp_device')
    secret = models.CharField(max_length=32)
    is_confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'TOTP デバイス'
        verbose_name_plural = 'TOTP デバイス'
    
    def __str__(self):
        return f"TOTP - {self.user.username}"
    
    def generate_qr_code(self):
        """QRコード生成"""
        import qrcode
        from io import BytesIO
        import base64
        
        totp = pyotp.TOTP(self.secret)
        uri = totp.provisioning_uri(
            name=self.user.email,
            issuer_name='Enova ID'
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_token(self, token):
        """トークン検証"""
        totp = pyotp.TOTP(self.secret)
        return totp.verify(token, valid_window=1)


class BackupCode(models.Model):
    """バックアップコード"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='backup_codes')
    code = models.CharField(max_length=12)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ('user', 'code')
        verbose_name = 'バックアップコード'
        verbose_name_plural = 'バックアップコード'
    
    def __str__(self):
        return f"Backup Code - {self.user.username}"


class WebAuthnDevice(models.Model):
    """WebAuthn デバイス（複数登録対応）"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='webauthn_devices')
    device_name = models.CharField(max_length=100)
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    
    is_primary = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'WebAuthn デバイス'
        verbose_name_plural = 'WebAuthn デバイス'
        ordering = ['-is_primary', '-last_used']
    
    def __str__(self):
        return f"{self.device_name} - {self.user.username}"


class EmailVerification(models.Model):
    """メール確認（任意）"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='email_verifications')
    email = models.EmailField()
    token = models.CharField(max_length=64, unique=True)
    is_verified = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        verbose_name = 'メール確認'
        verbose_name_plural = 'メール確認'
    
    def __str__(self):
        return f"{self.email} - {self.user.username}"
    
    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(32)
