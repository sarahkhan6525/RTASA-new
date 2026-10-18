import LoginFlow from "../components/LoginFlow";

export default function LoginRequester() {
  return (
    <LoginFlow
      kind="requester"
      title="Requester sign-in"
      subtitle="Sign in to request and recover records you're entitled to."
      portalPath="/portal/requester"
    />
  );
}
