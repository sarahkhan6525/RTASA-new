import LoginFlow from "../components/LoginFlow";

export default function LoginOwner() {
  return (
    <LoginFlow
      kind="owner"
      title="Owner sign-in"
      subtitle="Sign in to protect records and manage who can access them."
      portalPath="/portal/owner"
      allowCreate
    />
  );
}
