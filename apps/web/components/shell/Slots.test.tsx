import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";
import { Breadcrumbs } from "./Breadcrumbs";
import { SessionMenu } from "./SessionMenu";
import { CapabilityControl } from "./CapabilityControl";
import { ContextTabs } from "./ContextTabs";

describe("Structural Shell Slots (Non-authoritative)", () => {
  describe("WorkspaceSwitcher", () => {
    it("renders presentation scope without querying backend", () => {
      render(<WorkspaceSwitcher />);
      expect(
        screen.getByRole("region", { name: "Workspace Scope" })
      ).toBeInTheDocument();
      expect(screen.getByText("Scope: Presentation Shell")).toBeInTheDocument();
    });
  });

  describe("Breadcrumbs", () => {
    it("renders default route breadcrumbs", () => {
      render(<Breadcrumbs />);
      expect(
        screen.getByRole("navigation", { name: "Breadcrumbs" })
      ).toBeInTheDocument();
      expect(screen.getByText("W-014")).toBeInTheDocument();
      expect(screen.getByText("Presentation Shell")).toBeInTheDocument();
    });

    it("renders custom items with aria-current on the active item", () => {
      render(
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Settings", current: true },
          ]}
        />
      );
      expect(screen.getByText("Settings")).toHaveAttribute(
        "aria-current",
        "page"
      );
    });
  });

  describe("SessionMenu", () => {
    it("renders presentation mode session placeholder", () => {
      render(<SessionMenu />);
      expect(
        screen.getByRole("region", { name: "Session status" })
      ).toBeInTheDocument();
      expect(screen.getByText("Presentation Mode")).toBeInTheDocument();
    });
  });

  describe("CapabilityControl", () => {
    it("renders presentation tier capability indicator", () => {
      render(<CapabilityControl />);
      expect(
        screen.getByRole("region", { name: "Capability tier" })
      ).toBeInTheDocument();
      expect(
        screen.getByText("Presentation Shell Client")
      ).toBeInTheDocument();
    });
  });

  describe("ContextTabs", () => {
    it("renders context tablist with active tab", () => {
      render(
        <ContextTabs
          tabs={[
            { id: "overview", label: "Overview", active: true },
            { id: "details", label: "Details", active: false },
          ]}
        />
      );
      const tablist = screen.getByRole("tablist", { name: "View context tabs" });
      expect(tablist).toBeInTheDocument();

      const activeTab = screen.getByRole("tab", { name: "Overview" });
      expect(activeTab).toHaveAttribute("aria-selected", "true");

      const inactiveTab = screen.getByRole("tab", { name: "Details" });
      expect(inactiveTab).toHaveAttribute("aria-selected", "false");
    });
  });

  it("all slots have no accessibility violations", async () => {
    const { container } = render(
      <div>
        <WorkspaceSwitcher />
        <Breadcrumbs />
        <SessionMenu />
        <CapabilityControl />
        <ContextTabs />
      </div>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
