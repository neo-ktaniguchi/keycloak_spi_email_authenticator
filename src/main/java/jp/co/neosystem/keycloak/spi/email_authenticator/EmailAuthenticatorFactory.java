package jp.co.neosystem.keycloak.spi.email_authenticator;

import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * メールOTP認証SPI Factory
 */
public class EmailAuthenticatorFactory implements AuthenticatorFactory {
    /**
     * プロバイダID
     * 
     * Keycloak上でプロバイダを識別するための値
     */
    private static final String PROVIDER_ID = "email-authenticator";

    /**
     * 表示名
     */
    private static final String DISPLAY_NAME = "Email Authentication";

    /**
     * ヘルプテキスト
     */
    private static final String HELP_TEXT = "Email Authentication";

    /**
     * シングルトンインスタンス
     */
    private static final EmailAuthenticator SINGLETON = new EmailAuthenticator();

    /**
     * シングルトンインスタンス生成
     * 
     * @param arg0 Keycloakセッション
     */
    @Override
    public Authenticator create(KeycloakSession arg0) {
        return SINGLETON;
    }

    /**
     * プロバイダID取得
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * 表示名取得
     */
    @Override
    public String getDisplayType() {
        return DISPLAY_NAME;
    }

    /**
     * ヘルプテキスト取得
     */
    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public String getReferenceCategory() {
        return OTPCredentialModel.TYPE;
    }

    @Override
    public void init(Scope arg0) {
        // NOP
    }

    @Override
    public void postInit(KeycloakSessionFactory arg0) {
        // NOP
    }

    @Override
    public void close() {
        // NOP
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

}
