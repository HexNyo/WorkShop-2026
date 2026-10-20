import { useEffect, useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { ApiError } from "../../api/http";
import { useAuth } from "../../auth/AuthProvider";
import { Button, ErrorBanner, Field, Input } from "../../components/ui";
import { homeFor } from "../../routes";

export function LoginPage() {
  const { status, login, principal } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [cameraReady, setCameraReady] = useState(false);
  const video = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;
    let cancelled = false;
    navigator.mediaDevices
      ?.getUserMedia({ video: { width: 640, height: 480, facingMode: "user" } })
      .then((media) => {
        if (cancelled)
          return media.getTracks().forEach((track) => track.stop());
        stream = media;
        if (video.current) video.current.srcObject = media;
        setCameraReady(true);
      })
      .catch(() =>
        setError(
          new Error(
            "Caméra indisponible : autorisez l'accès à la webcam pour vous connecter.",
          ),
        ),
      );
    return () => {
      cancelled = true;
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, []);

  if (status === "authenticated" && principal) {
    const from = (location.state as { from?: string } | null)?.from;
    return <Navigate to={from ?? homeFor(principal.roles)} replace />;
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const frame = video.current!;
      const canvas = document.createElement("canvas");
      canvas.width = frame.videoWidth;
      canvas.height = frame.videoHeight;
      canvas.getContext("2d")!.drawImage(frame, 0, 0);
      await login(
        username,
        password,
        canvas.toDataURL("image/jpeg", 0.9).split(",")[1] ?? "",
      );
    } catch (failure) {
      setError(failure);
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  const faceMessages: Record<string, string> = {
    FACE_NOT_RECOGNIZED: "Visage non reconnu pour cet identifiant.",
    FACE_NOT_DETECTED:
      "Un seul visage, bien éclairé et de face, doit être visible.",
    FACE_LOCKED: `Trop d'échecs. Réessayez dans ${Math.ceil(((error instanceof ApiError && error.retryAfter) || 60) / 60)} min.`,
    PRE_AUTH_INVALID: "Vérification du visage expirée, recommencez.",
  };
  const message =
    error instanceof ApiError && error.code && error.code in faceMessages
      ? new ApiError({
          status: error.status,
          code: error.code,
          title: "Échec",
          detail: faceMessages[error.code],
        })
      : error instanceof ApiError && error.code === "ACCOUNT_LOCKED"
        ? new ApiError({
            status: 403,
            code: error.code,
            title: "Compte verrouillé",
            detail: `Trop de tentatives. Réessayez dans ${Math.ceil((error.retryAfter ?? 60) / 60)} min.`,
          })
        : error instanceof ApiError && error.code === "INVALID_CREDENTIALS"
          ? new ApiError({
              status: 401,
              code: error.code,
              title: "Échec",
              detail: "Identifiant ou mot de passe incorrect.",
            })
          : error;

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm md:max-w-3xl">
        <div className="mb-6 flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="h-8 w-8" />
          <div>
            <h1 className="text-lg font-semibold">RESILIENCE-ALPHA</h1>
            <p className="text-xs text-muted">
              Plateforme de paiement fictive · reprise autonome
            </p>
          </div>
        </div>
        <form
          onSubmit={submit}
          className="grid gap-5 rounded-lg border border-line bg-surface p-5 shadow-sm md:grid-cols-2 md:items-center"
          noValidate
        >
          <video
            ref={video}
            autoPlay
            playsInline
            muted
            aria-label="Aperçu de la webcam pour la vérification du visage"
            className="aspect-[4/3] w-full -scale-x-100 rounded-md border border-line bg-surface-2 object-cover"
          />
          <div className="space-y-4">
            <Field label="Identifiant" htmlFor="username">
              <Input
                id="username"
                name="username"
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
                minLength={3}
                autoFocus
              />
            </Field>
            <Field label="Mot de passe" htmlFor="password">
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </Field>
            <ErrorBanner error={message} title="Connexion refusée" />
            <Button
              type="submit"
              variant="primary"
              className="w-full"
              busy={busy}
              disabled={!username || !password || !cameraReady}
            >
              Se connecter
            </Button>
            <p className="text-[0.7rem] text-muted">
              Toutes les données sont fictives. La session est conservée en
              mémoire et renouvelée par un cookie sécurisé.
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
