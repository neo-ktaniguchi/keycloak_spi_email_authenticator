package jp.co.neosystem.keycloak.spi.email_authenticator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;

/**
 * メールOTP認証SPI
 */
@JBossLog
public class EmailAuthenticator extends AbstractUsernameFormAuthenticator {
    private static final int MAIL_OTP_CODE_LENGTH = 6;
    private static final int MAIL_OTP_CODE_TTL_VALUE = 300;
    private static final String MAIL_OTP_SESSION_KEY_CODE = "emailCode";
    private static final String MAIL_OTP_SESSION_KEY_CODE_TTL = "ttl";

    /**
     * 画面遷移前処理
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // 認証コードを生成
        String code = SecretGenerator.getInstance().randomString(MAIL_OTP_CODE_LENGTH, SecretGenerator.DIGITS);
        String codeTTL = Long.toString(System.currentTimeMillis() + (MAIL_OTP_CODE_TTL_VALUE * 1000L));

        // 生成した認証コードをセッションに格納
        AuthenticationSessionModel session = context.getAuthenticationSession();
        session.setAuthNote(MAIL_OTP_SESSION_KEY_CODE, code);
        session.setAuthNote(MAIL_OTP_SESSION_KEY_CODE_TTL, codeTTL);

        // メール送信準備
        EmailTemplateProvider emailTemplateProvider = context.getSession().getProvider(EmailTemplateProvider.class);
        emailTemplateProvider.setRealm(context.getRealm());
        emailTemplateProvider.setUser(context.getUser());

        // メール件名と本文への設定値を準備
        List<Object> subjectParams = List.of(context.getRealm().getName());
        Map<String, Object> mailBodyAttributes = new HashMap<>();
        mailBodyAttributes.put("username", context.getUser().getUsername());
        mailBodyAttributes.put("code", code);
        mailBodyAttributes.put("ttl", codeTTL);

        // メール送信
        try {
            emailTemplateProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
        } catch (EmailException e) {
            log.error("failed to send email.");
            throw new RuntimeException(e);
        }

        // メールOTP認証画面に遷移
        Response response = context.form().createForm("email-authenticator.ftl");
        context.challenge(response);
    }

    /**
     * 認証処理
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();
        if (!enabledUser(context, userModel)) {
            return;
        }

        // 認証コード検証
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel session = context.getAuthenticationSession();
        String code = session.getAuthNote(MAIL_OTP_SESSION_KEY_CODE);
        String codeTTL = session.getAuthNote(MAIL_OTP_SESSION_KEY_CODE_TTL);
        String enteredCode = formData.getFirst(MAIL_OTP_SESSION_KEY_CODE);

        // 認証コードチェック
        if (!code.equals(enteredCode)) {
            context.attempted();
            return;
        }

        context.getAuthenticationSession().removeAuthNote(MAIL_OTP_SESSION_KEY_CODE);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession arg0, RealmModel arg1, UserModel arg2) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession arg0, RealmModel arg1, UserModel arg2) {
        // NOP
    }
}
