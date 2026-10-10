import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

function useSystemLanguages(languages: string[]) {
  vi.spyOn(navigator, "languages", "get").mockReturnValue(languages);
}

afterEach(() => vi.restoreAllMocks());

describe("Маяк", () => {
  beforeEach(() => useSystemLanguages(["ru-RU"]));

  it("показывает понятный итог и сохраняет технические детали доступными", async () => {
    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Hotel Aurora" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Что важно знать")).toBeInTheDocument();
    expect(screen.getByText("Все параметры сети")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(
      screen.getByText("Кольца показывают уверенность в типе, не расстояние"),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText("Шлюз сети, Маршрутизатор"),
    ).toHaveAttribute("data-confidence", "high");
    expect(screen.getByText("Имя Wi-Fi пока скрыто системой")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Проверить сеть" })).toBeEnabled();
  });

  it("открывает список устройств и подробности выбранного соседа", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Hotel Aurora" });

    fireEvent.click(screen.getByRole("button", { name: /Устройства/ }));
    expect(
      screen.getByRole("heading", { name: "Видимые устройства" }),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /Reception Printer/ }),
    );
    expect(
      screen.getByLabelText("Сведения: Reception Printer"),
    ).toBeInTheDocument();
    expect(screen.getByText("Объявленные сервисы")).toBeInTheDocument();
  });

  it("объясняет границы углублённой проверки до запуска", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Hotel Aurora" });

    fireEvent.click(
      screen.getByRole("button", { name: "Углублённая проверка" }),
    );
    expect(
      screen.getByRole("dialog", { name: "Углублённая проверка" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Без подбора паролей и эксплуатации"),
    ).toBeInTheDocument();
  });

  it("не блокирует настройки без геопозиции", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Hotel Aurora" });

    fireEvent.click(screen.getByRole("button", { name: "Настройки" }));

    expect(
      screen.getByRole("heading", { name: "Настройки" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Ещё не запрошено")).toBeInTheDocument();
  });

  it("сразу снимает статус нового устройства после отметки знакомым", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Hotel Aurora" });

    fireEvent.click(screen.getByRole("button", { name: "Устройства" }));
    const deviceRow = screen.getByRole("button", { name: /iPhone гостя/ });
    expect(within(deviceRow).getByText("Новое")).toBeInTheDocument();

    fireEvent.click(deviceRow);
    const drawer = screen.getByLabelText("Сведения: iPhone гостя");
    fireEvent.click(within(drawer).getByRole("button", { name: "Знакомое" }));

    await waitFor(() => {
      const updatedRow = screen.getByRole("button", { name: /iPhone гостя/ });
      expect(within(updatedRow).queryByText("Новое")).not.toBeInTheDocument();
      expect(within(updatedRow).getByText("Знакомое")).toBeInTheDocument();
    });

    const devicesNav = screen.getByRole("button", { name: "Устройства" });
    expect(within(devicesNav).getByText("2")).toBeInTheDocument();
  });
});

describe("Mayak in English", () => {
  beforeEach(() => useSystemLanguages(["en-US", "en"]));

  it("follows an English system language by default", async () => {
    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Hotel Aurora" }),
    ).toBeInTheDocument();
    expect(screen.getByText("What to know")).toBeInTheDocument();
    expect(screen.getByText("All network details")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check network" })).toBeEnabled();
    expect(screen.getByLabelText(/, Router$/)).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
    expect(document.title).toBe("Mayak");
  });

  it("switches the interface language from settings", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Hotel Aurora" });

    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    fireEvent.change(screen.getByRole("combobox", { name: /Interface language/ }), {
      target: { value: "ru" },
    });

    expect(
      await screen.findByRole("heading", { name: "Настройки" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /Язык интерфейса/ })).toHaveValue("ru");
    expect(document.documentElement.lang).toBe("ru");
  });
});
