import logoUrl from "../../../assets/brand/icon.png";

const BrandMark = ({
  className = "",
  label = "Aydo Security",
}: {
  className?: string;
  label?: string;
}) => {
  return (
    <img
      src={logoUrl}
      alt={label}
      className={`h-full w-full object-contain ${className}`}
      aria-label={label}
      role="img"
    />
  );
};

export default BrandMark;
