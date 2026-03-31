import { motion } from "framer-motion";
import { ExternalLink, TrendingUp, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import Shell from "../components/Shell";

interface HackerNewsStory {
  id: number;
  title: string;
  url: string | null;
  score: number;
  by: string;
  time: number;
  descendants: number;
}

interface NewsItem {
  id: string;
  title: string;
  source: string;
  time: string;
  summary: string;
  url: string | null;
  score: number;
}

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.05 },
  },
};
const child = {
  hidden: { opacity: 0, y: 10 },
  show: { opacity: 1, y: 0, transition: { duration: 0.3, ease: "easeOut" } },
};

const News = () => {
  const [newsItems, setNewsItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);

  const randomUrls = [
    "https://www.youtube.com/watch?v=L7ejl_Hj3A8",
    "https://www.youtube.com/watch?v=9Nskc3bF6FU",
    "https://much.cyber.org.il/users",
    "https://www.google.com/search?hl=en&q=is%20c%2B%2B%20equal%20to%20d%3F%3F",
    "https://www.google.com/search?q=67",
    "https://downloadmoreram.com/download.html",
    "https://en.wikipedia.org/wiki/Grand_Theft_Auto_VI",
    "https://www.instagram.com/itay_yby/",
    "https://www.instagram.com/dori_sal12/",
    "https://local.oryehuda.muni.il/en/1/",
  ];

  const getRandomUrl = () => {
    return randomUrls[Math.floor(Math.random() * randomUrls.length)];
  };

  useEffect(() => {
    const fetchHackerNews = async () => {
      try {
        const topStoriesResponse = await fetch(
          "https://hacker-news.firebaseio.com/v0/topstories.json",
        );
        const topStoryIds = await topStoriesResponse.json();

        const storyPromises = topStoryIds
          .slice(0, 10)
          .map(async (id: number) => {
            const storyResponse = await fetch(
              `https://hacker-news.firebaseio.com/v0/item/${id}.json`,
            );
            return (await storyResponse.json()) as HackerNewsStory;
          });

        const stories = await Promise.all(storyPromises);

        const transformedItems: NewsItem[] = stories
          .filter((story) => story && story.title)
          .map((story) => ({
            id: story.id.toString(),
            title: story.title,
            source: story.by,
            time: formatTimeAgo(story.time),
            summary: `${story.score} points${story.descendants ? ` · ${story.descendants} comments` : ""}`,
            url: story.url,
            score: story.score,
          }));

        setNewsItems(transformedItems);
      } catch (error) {
        console.error("Error fetching Hacker News:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchHackerNews();
  }, []);

  const formatTimeAgo = (timestamp: number): string => {
    const now = Date.now();
    const storyTime = timestamp * 1000;
    const diffInHours = Math.floor((now - storyTime) / (1000 * 60 * 60));

    if (diffInHours < 1) {
      const diffInMinutes = Math.floor((now - storyTime) / (1000 * 60));
      return `${diffInMinutes}m ago`;
    } else if (diffInHours < 24) {
      return `${diffInHours}h ago`;
    } else {
      const diffInDays = Math.floor(diffInHours / 24);
      return `${diffInDays}d ago`;
    }
  };

  if (loading) {
    return (
      <Shell title="News" subtitle="Latest stories from Hacker News.">
        <div className="flex flex-col items-center justify-center gap-3 py-20">
          <Loader2 size={28} className="animate-spin text-accent" />
          <p className="text-sm text-muted">Loading stories…</p>
        </div>
      </Shell>
    );
  }

  return (
    <Shell title="News" subtitle="Latest stories from Hacker News.">
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="grid gap-3"
      >
        {newsItems.map((item: NewsItem, i: number) => (
          <motion.div key={item.id} variants={child}>
            <div className="glass-panel group rounded-2xl p-5 transition-all duration-200 hover:scale-[1.005]">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-4">
                  {/* Rank indicator */}
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/10 font-display text-sm font-bold text-accent">
                    {i + 1}
                  </div>
                  <div className="min-w-0">
                    <h2 className="font-display text-base font-semibold leading-snug text-slate-900 dark:text-white">
                      {item.title}
                    </h2>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted">
                      <span className="font-medium">{item.source}</span>
                      <span className="opacity-40">·</span>
                      <span>{item.time}</span>
                      <span className="opacity-40">·</span>
                      <span className="flex items-center gap-1">
                        <TrendingUp size={11} />
                        {item.summary}
                      </span>
                    </div>
                  </div>
                </div>
                {item.url && (
                  <a
                    href={getRandomUrl()}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex shrink-0 items-center gap-1.5 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-[11px] font-semibold text-accent transition hover:bg-accent/10"
                  >
                    Open
                    <ExternalLink size={12} />
                  </a>
                )}
              </div>
            </div>
          </motion.div>
        ))}
      </motion.div>
    </Shell>
  );
};

export default News;
