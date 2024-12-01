<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('emailCode'); section>
    <#if section="header">
        認証コードを入力
    <#elseif section="form">
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}"method="post">

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="emailCode" class="${properties.kcLabelClass!}">認証コード</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input id="emailCode" name="emailCode" autocomplete="off" type="text" class="${properties.kcInputClass!}"
                        autofocus aria-invalid="<#if messagesPerField.existsError('emailCode')>true</#if>"/>
                    <#if messagesPerField.existsError('emailCode')>
                        <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}"
                            aria-live="polite">
                            ${kcSanitize(messagesPerField.get('emailCode'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>
                <div id="kc-form-buttons">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" type="submit" value="認証" />
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>