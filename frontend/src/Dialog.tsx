import { useEffect, useRef, type ReactNode } from "react";

/** Native modality supplies focus trapping, Escape support and an inert background. */
export function Dialog({
  children,
  onClose,
  busy,
}: {
  children: ReactNode;
  onClose: () => void;
  busy: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = ref.current!;
    const opener =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    element.showModal();
    element.querySelector<HTMLInputElement>("input:not(:disabled)")?.focus();
    return () => {
      element.close();
      if (opener?.isConnected && !element.contains(opener))
        opener.focus({ preventScroll: true });
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="modal-dialog"
      aria-labelledby="project-dialog-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
      onClick={(event) => {
        if (!busy && event.target === event.currentTarget) onClose();
      }}
    >
      {children}
    </dialog>
  );
}
