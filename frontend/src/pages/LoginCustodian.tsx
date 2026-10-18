import LoginFlow from "../components/LoginFlow";

export default function LoginCustodian() {
  return (
    <LoginFlow
      kind="custodian"
      title="Custodian sign-in"
      subtitle="Sign in to review and approve pending access requests for records you hold a share of."
      portalPath="/portal/custodian"
    />
  );
}
