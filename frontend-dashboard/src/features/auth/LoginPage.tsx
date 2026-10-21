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
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,rgba(56,189,248,0.18),transparent_55%),radial-gradient(ellipse_at_bottom,rgba(167,139,250,0.15),transparent_55%)] px-4">
      <div className="w-full max-w-sm">
        <h1 className="mb-6 bg-gradient-to-r from-sky-400 to-violet-400 bg-clip-text text-center text-2xl font-semibold tracking-tight text-transparent">
          Workshop 2026
        </h1>
        <form
          onSubmit={submit}
          className="space-y-5 rounded-xl border border-line bg-surface p-6 shadow-sm"
          noValidate
        >
          <video
            ref={video}
            autoPlay
            playsInline
            muted
            aria-label="Aperçu de la webcam pour la vérification du visage"
            className="mx-auto aspect-square w-32 -scale-x-100 rounded-full border border-line bg-surface-2 object-cover"
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
          </div>
        </form>
        <p className="mt-4 text-center text-[0.7rem] text-muted">Données fictives</p>
      </div>
    </div>
  );
}
