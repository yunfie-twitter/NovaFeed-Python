from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, AuthenticationForm
from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, label='メールアドレス')
    nickname = forms.CharField(
        required=False,
        max_length=50,
        label='ニックネーム',
        help_text='表示用の名前（日本語可）'
    )
    
    class Meta:
        model = CustomUser
        fields = ('username', 'nickname', 'email', 'password1', 'password2')
        labels = {
            'username': 'ユーザーID',
        }
        help_texts = {
            'username': 'ログイン用のID（半角英数字のみ、15文字以内）',
        }
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError('このメールアドレスは既に登録されています')
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if CustomUser.objects.filter(username=username).exists():
            raise forms.ValidationError('このユーザーIDは既に使用されています')
        return username

class CustomUserChangeForm(UserChangeForm):
    password = None  # パスワードフィールドを非表示
    
    class Meta:
        model = CustomUser
        fields = ('username', 'nickname', 'email', 'phone_number', 'profile_image', 'bio')
        labels = {
            'username': 'ユーザーID',
            'nickname': 'ニックネーム',
            'email': 'メールアドレス',
            'phone_number': '電話番号',
            'profile_image': 'プロフィール画像',
            'bio': '自己紹介',
        }
        help_texts = {
            'username': 'ログイン用のID（変更非推奨）',
            'nickname': '表示用の名前（日本語可）',
        }
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'readonly': 'readonly',  # ユーザーIDは変更不可にする
            }),
            'nickname': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例: 太郎'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'email@example.com'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '090-1234-5678'
            }),
            'bio': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': '自己紹介を入力してください'
            }),
        }

class CustomLoginForm(AuthenticationForm):
    username = forms.CharField(
        label='ユーザーID',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ユーザーID'})
    )
    password = forms.CharField(
        label='パスワード',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'パスワード'})
    )
